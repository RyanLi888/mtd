#!/usr/bin/env python3
"""OpenSSL-visible TLS probe.

Hooks SSL_read/SSL_write via eBPF uprobe to extract Stratum markers
from TLS-encrypted mining traffic. Works only with dynamically-linked
OpenSSL (libssl.so).

Output: MarkerSummary with visibility_mode='openssl_visible_tls'.

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

MAX_PAYLOAD = 432

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct data_t {
    u64 ts;
    u32 pid;
    u32 tid;
    char comm[16];
    char direction[4];
    int bytes;
    char payload[432];
};

struct read_args_t {
    const void *buf;
    int num;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(pending_read, u64, struct read_args_t, 256);

int trace_ssl_write_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    if (num <= 0) return 0;

    struct data_t data;
    data.ts = bpf_ktime_get_ns();
    data.pid = pid;
    data.tid = (u32)pid_tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(data.direction, "send", 4);
    data.bytes = num;
    bpf_probe_read_user(&data.payload, sizeof(data.payload), buf);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_ssl_read_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    if (num <= 0) return 0;

    struct read_args_t args = {};
    args.buf = buf;
    args.num = num;
    pending_read.update(&pid_tgid, &args);
    return 0;
}

int trace_ssl_read_return(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    struct read_args_t *args = pending_read.lookup(&pid_tgid);
    if (!args) return 0;

    u32 pid = pid_tgid >> 32;
    struct data_t data;
    data.ts = bpf_ktime_get_ns();
    data.pid = pid;
    data.tid = (u32)pid_tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(data.direction, "recv", 4);
    data.bytes = ret;
    bpf_probe_read_user(&data.payload, sizeof(data.payload), args->buf);

    events.perf_submit(ctx, &data, sizeof(data));
    pending_read.delete(&pid_tgid);
    return 0;
}
"""

# ── Probe Class ──────────────────────────────────────────────────────────────

class TlsOpenSSLProbe:
    """TLS semantic probe using eBPF uprobe on SSL_read/SSL_write."""

    def __init__(self, target_pid: int, duration: int, comm_filter: str = "",
                 early_confirm=False, early_check_interval=5,
                 early_min_job=1, early_min_submit=1, early_min_assoc=1):
        self.target_pid = target_pid
        self.duration = duration
        self.comm_filter = comm_filter
        self._running = True
        self._early_confirm = early_confirm
        self._early_check_interval = early_check_interval
        self._early_min_job = early_min_job
        self._early_min_submit = early_min_submit
        self._early_min_assoc = early_min_assoc
        self._early_confirmed = False
        self._early_confirm_reason = ""
        self._actual_duration = 0.0

        # Session salt for token association
        self._session_salt = os.urandom(16).hex()

        # Active job tokens for association
        self._active_job_tokens = set()

        # Prefix scan counters
        self._prefix_counters = {
            "prefix_scan_attempts": 0,
            "prefix_scan_success": 0,
            "prefix_truncated_count": 0,
            "read_side_job_marker_count": 0,
            "write_side_submit_marker_count": 0,
            "associated_submit_count": 0,
            "association_mismatch_count": 0,
            "real_tls_job_side_semantic_count": 0,
            "real_tls_submit_side_semantic_count": 0,
            "prefix_method_field_count": 0,
            "prefix_mining_notify_count": 0,
            "prefix_mining_submit_count": 0,
            "prefix_method_job_count": 0,
            "prefix_method_submit_count": 0,
            "prefix_method_login_count": 0,
            "prefix_result_field_count": 0,
            "prefix_error_field_count": 0,
            "prefix_job_field_count": 0,
            "prefix_job_id_field_count": 0,
            "prefix_blob_field_count": 0,
            "prefix_target_field_count": 0,
            "prefix_seed_hash_field_count": 0,
            "prefix_height_field_count": 0,
        }

        # Debug counters
        self._counters = {
            "ssl_write_entry_count": 0,
            "ssl_write_buffer_read_success": 0,
            "ssl_write_buffer_read_fail": 0,
            "ssl_write_bytes_seen": 0,
            "ssl_read_return_count": 0,
            "ssl_read_buffer_read_success": 0,
            "ssl_read_buffer_read_fail": 0,
            "ssl_read_bytes_seen": 0,
        }

    def _compute_job_token(self, job_id: str) -> str:
        """SHA256(session_salt || job_id)[:16] — salt never saved."""
        h = hashlib.sha256(self._session_salt.encode() + job_id.encode()).hexdigest()[:16]
        return h

    def _prefix_scan_payload(self, payload_str: str, direction: str, original_bytes: int):
        """Scan payload prefix for method/marker strings. No raw payload saved."""
        self._prefix_counters["prefix_scan_attempts"] += 1

        is_truncated = original_bytes > MAX_PAYLOAD
        if is_truncated:
            self._prefix_counters["prefix_truncated_count"] += 1

        # Scan for markers
        has_method = '"method"' in payload_str
        has_mining_notify = '"mining.notify"' in payload_str
        has_mining_submit = '"mining.submit"' in payload_str
        has_method_job = re.search(r'"method"\s*:\s*"job"', payload_str) is not None
        has_method_submit = re.search(r'"method"\s*:\s*"submit"', payload_str) is not None
        has_result = '"result"' in payload_str
        has_job = '"job"' in payload_str
        has_job_id = '"job_id"' in payload_str
        has_blob = '"blob"' in payload_str

        # Update counters
        if has_method: self._prefix_counters["prefix_method_field_count"] += 1
        if has_mining_notify: self._prefix_counters["prefix_mining_notify_count"] += 1
        if has_mining_submit: self._prefix_counters["prefix_mining_submit_count"] += 1
        if has_method_job: self._prefix_counters["prefix_method_job_count"] += 1
        if has_method_submit: self._prefix_counters["prefix_method_submit_count"] += 1
        if has_result: self._prefix_counters["prefix_result_field_count"] += 1
        if has_job: self._prefix_counters["prefix_job_field_count"] += 1
        if has_job_id: self._prefix_counters["prefix_job_id_field_count"] += 1
        if has_blob: self._prefix_counters["prefix_blob_field_count"] += 1

        # Extract job_id for token association (value never saved)
        job_id_match = re.search(r'"job_id"\s*:\s*"([^"]+)"', payload_str)
        job_id_value = job_id_match.group(1) if job_id_match else None

        # Job-side semantic (read direction)
        is_job_side = (direction == "recv" and (
            has_mining_notify
            or has_method_job
            or (has_result and has_job)
            or (has_job_id and has_blob)
        ))
        if is_job_side:
            self._prefix_counters["read_side_job_marker_count"] += 1
            self._prefix_counters["real_tls_job_side_semantic_count"] += 1
            if job_id_value:
                token = self._compute_job_token(job_id_value)
                self._active_job_tokens.add(token)

        # Submit-side semantic (write direction)
        is_submit_side = (direction == "send" and (
            has_mining_submit
            or has_method_submit
        ))
        if is_submit_side:
            self._prefix_counters["write_side_submit_marker_count"] += 1
            self._prefix_counters["real_tls_submit_side_semantic_count"] += 1
            if job_id_value:
                token = self._compute_job_token(job_id_value)
                if token in self._active_job_tokens:
                    self._prefix_counters["associated_submit_count"] += 1
                else:
                    self._prefix_counters["association_mismatch_count"] += 1

        if has_method or has_result or has_error or has_job:
            self._prefix_counters["prefix_scan_success"] += 1

    def _process_event(self, cpu, data, size):
        """Process a BPF event from SSL_read/SSL_write."""
        event = self.b["events"].event(data)

        direction = event.direction.decode("utf-8", errors="replace").rstrip("\x00")
        max_buf = len(event.payload)
        actual_len = min(event.bytes, max_buf)
        payload_bytes = bytes(event.payload)[:actual_len]

        # Counter tracking
        if direction == "send":
            self._counters["ssl_write_entry_count"] += 1
            self._counters["ssl_write_buffer_read_success"] += 1
            self._counters["ssl_write_bytes_seen"] += event.bytes
        elif direction == "recv":
            self._counters["ssl_read_return_count"] += 1
            self._counters["ssl_read_buffer_read_success"] += 1
            self._counters["ssl_read_bytes_seen"] += event.bytes

        # Apply comm filter
        comm = event.comm.decode("utf-8", errors="replace").rstrip("\x00")
        if self.comm_filter and self.comm_filter not in comm:
            return

        # Decode payload
        try:
            payload_str = payload_bytes.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            return

        if not payload_str:
            return

        # Prefix scan
        self._prefix_scan_payload(payload_str, direction, event.bytes)

    def run(self):
        """Run the probe and return MarkerSummary."""
        if not HAS_BPF:
            print("[ERROR] BCC not available")
            return self._empty_summary()

        # Find target process and SSL library
        import psutil
        proc = psutil.Process(self.target_pid)
        ssl_lib = None
        for lib in proc.memory_maps():
            if 'libssl' in lib.path:
                ssl_lib = lib.path
                break

        if not ssl_lib:
            print(f"[ERROR] No libssl found for PID {self.target_pid}")
            return self._empty_summary()

        print(f"[tls_probe] Target PID: {self.target_pid}")
        print(f"[tls_probe] SSL library: {ssl_lib}")

        # Compile and attach BPF
        self.b = BPF(text=BPF_PROGRAM)
        pid = self.target_pid

        self.b.attach_uprobe(name=ssl_lib, sym="SSL_write", fn_name="trace_ssl_write_entry", pid=pid)
        self.b.attach_uprobe(name=ssl_lib, sym="SSL_read", fn_name="trace_ssl_read_entry", pid=pid)
        self.b.attach_uretprobe(name=ssl_lib, sym="SSL_read", fn_name="trace_ssl_read_return", pid=pid)

        print("[tls_probe] Attached uprobes to SSL_write/SSL_read")

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
                print(f"[tls_probe] Error polling: {e}")
                break

            # Early confirm check
            if self._early_confirm:
                now = time.time()
                if now - last_early_check >= self._early_check_interval:
                    last_early_check = now
                    psc = self._prefix_counters
                    if (psc["read_side_job_marker_count"] >= self._early_min_job and
                            psc["write_side_submit_marker_count"] >= self._early_min_submit and
                            psc["associated_submit_count"] >= self._early_min_assoc):
                        self._early_confirmed = True
                        self._early_confirm_reason = "job_submit_association_seen"
                        self._actual_duration = now - start
                        print(f"[tls_probe] Early confirmed at {self._actual_duration:.1f}s")
                        break

        if self._actual_duration == 0.0:
            self._actual_duration = time.time() - start

        return self._build_summary()

    def _empty_summary(self):
        """Return empty summary on failure."""
        from layerminer.schema import MarkerSummary
        return MarkerSummary(visibility_mode="openssl_visible_tls")

    def _build_summary(self):
        """Build MarkerSummary from counters."""
        from layerminer.schema import MarkerSummary
        psc = self._prefix_counters
        return MarkerSummary(
            visibility_mode="openssl_visible_tls",
            job_marker_count=psc["read_side_job_marker_count"],
            submit_marker_count=psc["write_side_submit_marker_count"],
            associated_submit_count=psc["associated_submit_count"],
            association_mismatch_count=psc["association_mismatch_count"],
            raw_payload_saved=False,
        )


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OpenSSL-visible TLS probe")
    parser.add_argument("--pid", type=int, required=True, help="Target process PID")
    parser.add_argument("--duration", type=int, default=300, help="Probe duration (seconds)")
    parser.add_argument("--comm-filter", type=str, default="", help="Filter by comm name")
    parser.add_argument("--output", type=str, default="", help="Output JSON path")
    parser.add_argument("--early-confirm", action="store_true", help="Enable early confirm exit")
    parser.add_argument("--early-check-interval", type=int, default=5, help="Early check interval (sec)")
    parser.add_argument("--early-min-job", type=int, default=1, help="Min job markers for early confirm")
    parser.add_argument("--early-min-submit", type=int, default=1, help="Min submit markers for early confirm")
    parser.add_argument("--early-min-assoc", type=int, default=1, help="Min associated submits for early confirm")
    args = parser.parse_args()

    probe = TlsOpenSSLProbe(
        args.pid, args.duration, args.comm_filter,
        early_confirm=args.early_confirm,
        early_check_interval=args.early_check_interval,
        early_min_job=args.early_min_job,
        early_min_submit=args.early_min_submit,
        early_min_assoc=args.early_min_assoc,
    )
    summary = probe.run()

    print(f"[tls_probe] job={summary.job_marker_count} submit={summary.submit_marker_count} assoc={summary.associated_submit_count}")

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
                    "prefix_scan_counters": probe._prefix_counters,
                }, f, indent=2)
            print(f"[tls_probe] Output: {args.output}")
        except Exception as e:
            print(f"[tls_probe] Error writing output: {e}")


if __name__ == "__main__":
    main()
