#!/usr/bin/env python3
"""Plaintext Stratum probe using tracepoints.

Uses tracepoint:syscalls:sys_enter_write for submit direction,
tracepoint:syscalls:sys_enter_read + sys_exit_read for job direction.

Confirmed by IO path audit: XMRig plaintext uses write()/read() syscalls.

Output: MarkerSummary with visibility_mode='plaintext_stratum'.

Privacy: never saves raw payload, wallet, job_id, nonce, result, blob.
"""

import argparse
import ctypes
import hashlib
import json
import os
import re
import signal
import sys
import time

try:
    from bcc import BPF
    HAS_BPF = True
except ImportError:
    HAS_BPF = False

# ── BPF Program ──────────────────────────────────────────────────────────────

MAX_PAYLOAD = 384

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 direction;  // 0=send, 1=recv
    int fd;
    int bytes;
    char payload[384];
};

struct read_buf_t {
    int fd;
    char *buf;
};

BPF_HASH(target_pid_map, u32, u32, 1);
BPF_HASH(read_bufs, u64, struct read_buf_t, 1024);
BPF_PERF_OUTPUT(events);

static __always_inline int is_target() {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *val = target_pid_map.lookup(&key);
    if (val && *val == pid) return 1;
    return 0;
}

// write() entry — capture submit direction payload
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    if (!is_target()) return 0;

    int count = args->count;
    if (count <= 0) return 0;

    struct event_t evt = {};
    evt.direction = 0;  // send
    evt.fd = args->fd;
    evt.bytes = count;
    bpf_probe_read_user(&evt.payload, sizeof(evt.payload), args->buf);
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// read() entry — save buffer pointer for return
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    if (!is_target()) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_buf_t rb = {};
    rb.fd = args->fd;
    rb.buf = args->buf;
    read_bufs.update(&pid_tgid, &rb);
    return 0;
}

// read() return — read the filled buffer for job direction
TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    if (!is_target()) return 0;

    long ret = args->ret;
    if (ret <= 0) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_buf_t *rb = read_bufs.lookup(&pid_tgid);
    if (!rb) return 0;

    struct event_t evt = {};
    evt.direction = 1;  // recv
    evt.fd = rb->fd;
    evt.bytes = ret;
    bpf_probe_read_user(&evt.payload, sizeof(evt.payload), rb->buf);
    events.perf_submit(args, &evt, sizeof(evt));
    read_bufs.delete(&pid_tgid);
    return 0;
}
"""

# ── Probe Class ──────────────────────────────────────────────────────────────

class PlaintextStratumProbe:
    """Plaintext Stratum probe using tracepoints on write()/read() syscalls."""

    def __init__(self, target_pid: int, duration: int,
                 early_confirm=False, early_check_interval=5,
                 early_min_job=1, early_min_submit=1, early_min_assoc=1):
        self.target_pid = target_pid
        self.duration = duration
        self._running = True
        self._early_confirm = early_confirm
        self._early_check_interval = early_check_interval
        self._early_min_job = early_min_job
        self._early_min_submit = early_min_submit
        self._early_min_assoc = early_min_assoc
        self._early_confirmed = False
        self._early_confirm_reason = ""
        self._actual_duration = 0.0

        self._session_salt = os.urandom(16).hex()
        self._active_job_tokens = set()

        self._counters = {
            "write_count": 0,
            "read_count": 0,
            "payload_nonempty_send": 0,
            "payload_nonempty_recv": 0,
            "job_marker_count": 0,
            "submit_marker_count": 0,
            "associated_submit_count": 0,
            "association_mismatch_count": 0,
        }

    def _compute_job_token(self, job_id: str) -> str:
        """SHA256(session_salt || job_id)[:16] — salt never saved."""
        return hashlib.sha256(self._session_salt.encode() + job_id.encode()).hexdigest()[:16]

    def _scan_markers(self, payload_str: str, direction: str):
        """Scan payload for Stratum markers. No raw payload saved."""
        has_mining_notify = '"mining.notify"' in payload_str
        has_method_job = re.search(r'"method"\s*:\s*"job"', payload_str) is not None
        has_job_id = '"job_id"' in payload_str
        has_blob = '"blob"' in payload_str
        has_result_with_job = '"result"' in payload_str and '"job"' in payload_str

        is_job_side = (direction == "recv" and (
            has_mining_notify or has_method_job or has_result_with_job
            or (has_job_id and has_blob)
        ))

        has_mining_submit = '"mining.submit"' in payload_str
        has_method_submit = re.search(r'"method"\s*:\s*"submit"', payload_str) is not None

        is_submit_side = (direction == "send" and (
            has_mining_submit or has_method_submit
        ))

        job_id_match = re.search(r'"job_id"\s*:\s*"([^"]+)"', payload_str)
        job_id_value = job_id_match.group(1) if job_id_match else None

        if is_job_side:
            self._counters["job_marker_count"] += 1
            if job_id_value:
                token = self._compute_job_token(job_id_value)
                self._active_job_tokens.add(token)

        if is_submit_side:
            self._counters["submit_marker_count"] += 1
            if job_id_value:
                token = self._compute_job_token(job_id_value)
                if token in self._active_job_tokens:
                    self._counters["associated_submit_count"] += 1
                else:
                    self._counters["association_mismatch_count"] += 1

    def _process_event(self, cpu, data, size):
        """Process a BPF event."""
        event = self.b["events"].event(data)
        direction = "send" if event.direction == 0 else "recv"

        if direction == "send":
            self._counters["write_count"] += 1
        else:
            self._counters["read_count"] += 1

        actual_len = min(event.bytes, MAX_PAYLOAD)
        if actual_len <= 0:
            return

        payload_bytes = bytes(event.payload)[:actual_len]
        try:
            payload_str = payload_bytes.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            return

        if not payload_str:
            return

        if direction == "send":
            self._counters["payload_nonempty_send"] += 1
        else:
            self._counters["payload_nonempty_recv"] += 1

        self._scan_markers(payload_str, direction)

    def run(self):
        """Run the probe and return MarkerSummary."""
        if not HAS_BPF:
            print("[plaintext_probe] ERROR: BCC not available")
            return self._empty_summary()

        print(f"[plaintext_probe] Target PID: {self.target_pid}")
        print(f"[plaintext_probe] Duration: {self.duration}s")

        self.b = BPF(text=BPF_PROGRAM)

        target_key = ctypes.c_int(0)
        target_val = ctypes.c_uint32(self.target_pid)
        self.b["target_pid_map"][target_key] = target_val

        print("[plaintext_probe] Attached tracepoints: sys_enter_write, sys_enter_read, sys_exit_read")

        self.b["events"].open_perf_buffer(self._process_event)

        def handler(sig, frame):
            self._running = False
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

        start = time.time()
        last_early_check = start
        while self._running and time.time() - start < self.duration:
            try:
                self.b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[plaintext_probe] Error polling: {e}")
                break

            # Early confirm check
            if self._early_confirm:
                now = time.time()
                if now - last_early_check >= self._early_check_interval:
                    last_early_check = now
                    c = self._counters
                    if (c["job_marker_count"] >= self._early_min_job and
                            c["submit_marker_count"] >= self._early_min_submit and
                            c["associated_submit_count"] >= self._early_min_assoc):
                        self._early_confirmed = True
                        self._early_confirm_reason = "job_submit_association_seen"
                        self._actual_duration = now - start
                        print(f"[plaintext_probe] Early confirmed at {self._actual_duration:.1f}s")
                        break

        if self._actual_duration == 0.0:
            self._actual_duration = time.time() - start

        return self._build_summary()

    def _empty_summary(self):
        from layerminer.schema import MarkerSummary
        return MarkerSummary(visibility_mode="plaintext_stratum")

    def _build_summary(self):
        from layerminer.schema import MarkerSummary
        return MarkerSummary(
            visibility_mode="plaintext_stratum",
            job_marker_count=self._counters["job_marker_count"],
            submit_marker_count=self._counters["submit_marker_count"],
            associated_submit_count=self._counters["associated_submit_count"],
            association_mismatch_count=self._counters["association_mismatch_count"],
            raw_payload_saved=False,
        )


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Plaintext Stratum probe (tracepoint)")
    parser.add_argument("--pid", type=int, required=True, help="Target process PID")
    parser.add_argument("--tgid", type=int, default=0, help="Alias for --pid")
    parser.add_argument("--duration", type=int, default=300, help="Probe duration (seconds)")
    parser.add_argument("--output", type=str, default="", help="Output JSON path")
    parser.add_argument("--early-confirm", action="store_true", help="Enable early confirm exit")
    parser.add_argument("--early-check-interval", type=int, default=5, help="Early check interval (sec)")
    parser.add_argument("--early-min-job", type=int, default=1, help="Min job markers for early confirm")
    parser.add_argument("--early-min-submit", type=int, default=1, help="Min submit markers for early confirm")
    parser.add_argument("--early-min-assoc", type=int, default=1, help="Min associated submits for early confirm")
    args = parser.parse_args()

    target_pid = args.pid if args.pid else args.tgid
    if not target_pid:
        print("[plaintext_probe] ERROR: --pid or --tgid required")
        sys.exit(1)

    probe = PlaintextStratumProbe(
        target_pid, args.duration,
        early_confirm=args.early_confirm,
        early_check_interval=args.early_check_interval,
        early_min_job=args.early_min_job,
        early_min_submit=args.early_min_submit,
        early_min_assoc=args.early_min_assoc,
    )
    summary = probe.run()

    print(f"[plaintext_probe] job={summary.job_marker_count} submit={summary.submit_marker_count} assoc={summary.associated_submit_count}")
    print(f"[plaintext_probe] write={probe._counters['write_count']} read={probe._counters['read_count']} "
          f"payload_send={probe._counters['payload_nonempty_send']} payload_recv={probe._counters['payload_nonempty_recv']}")

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump({
                    "visibility_mode": summary.visibility_mode,
                    "job_marker_count": summary.job_marker_count,
                    "submit_marker_count": summary.submit_marker_count,
                    "associated_submit_count": summary.associated_submit_count,
                    "association_mismatch_count": summary.association_mismatch_count,
                    "raw_payload_saved": summary.raw_payload_saved,
                    "early_confirmed": probe._early_confirmed,
                    "early_confirm_reason": probe._early_confirm_reason,
                    "actual_observe_duration_sec": round(probe._actual_duration, 1),
                    "debug_counters": probe._counters,
                }, f, indent=2)
            print(f"[plaintext_probe] Output: {args.output}")
        except Exception as e:
            print(f"[plaintext_probe] Error writing output: {e}")


if __name__ == "__main__":
    main()
