#!/usr/bin/env python3
"""Plaintext IO path audit.

Count-only probe: determines which syscall/kernel paths XMRig actually
uses for plaintext TCP I/O. Does NOT read payload, does NOT save raw data.

Usage:
    sudo python3 probes/plaintext_io_path_audit.py --pid <PID> --duration 30

Output:
    JSON with per-path event counts. raw_payload_saved always false.
"""

import argparse
import ctypes
import json
import signal
import sys
import time

try:
    from bcc import BPF
    HAS_BPF = True
except ImportError:
    HAS_BPF = False

# ── BPF Program: count-only, no payload read ────────────────────────────────

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

BPF_HASH(target_pid_map, u32, u32, 1);
BPF_ARRAY(counters, u64, 12);

// Counter indices:
// 0: sys_write   1: sys_read   2: sys_writev   3: sys_readv
// 4: sys_sendto  5: sys_recvfrom  6: sys_sendmsg  7: sys_recvmsg
// 8: sys_send    9: sys_recv   10: tcp_sendmsg   11: tcp_recvmsg

static __always_inline int is_target() {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *val = target_pid_map.lookup(&key);
    if (val && *val == pid) return 1;
    return 0;
}

static __always_inline void inc_counter(int idx) {
    u64 *val = counters.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}

// --- sys_write / sys_read ---
int trace_sys_write(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(0);
    return 0;
}
int trace_sys_read(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(1);
    return 0;
}

// --- sys_writev / sys_readv ---
int trace_sys_writev(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(2);
    return 0;
}
int trace_sys_readv(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(3);
    return 0;
}

// --- sys_sendto / sys_recvfrom ---
int trace_sys_sendto(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(4);
    return 0;
}
int trace_sys_recvfrom(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(5);
    return 0;
}

// --- sys_sendmsg / sys_recvmsg ---
int trace_sys_sendmsg(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(6);
    return 0;
}
int trace_sys_recvmsg(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(7);
    return 0;
}

// --- sys_send / sys_recv ---
int trace_sys_send(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(8);
    return 0;
}
int trace_sys_recv(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(9);
    return 0;
}

// --- tcp_sendmsg / tcp_recvmsg ---
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(10);
    return 0;
}
int trace_tcp_recvmsg(struct pt_regs *ctx) {
    if (!is_target()) return 0;
    inc_counter(11);
    return 0;
}
"""

COUNTER_NAMES = [
    "sys_write_count", "sys_read_count",
    "sys_writev_count", "sys_readv_count",
    "sys_sendto_count", "sys_recvfrom_count",
    "sys_sendmsg_count", "sys_recvmsg_count",
    "sys_send_count", "sys_recv_count",
    "tcp_sendmsg_count", "tcp_recvmsg_count",
]

# Syscall name → (kprobe_event, fallback_event)
SYSCALL_PROBES = [
    ("sys_write", "trace_sys_write", "__x64_sys_write"),
    ("sys_read", "trace_sys_read", "__x64_sys_read"),
    ("sys_writev", "trace_sys_writev", "__x64_sys_writev"),
    ("sys_readv", "trace_sys_readv", "__x64_sys_readv"),
    ("sys_sendto", "trace_sys_sendto", "__x64_sys_sendto"),
    ("sys_recvfrom", "trace_sys_recvfrom", "__x64_sys_recvfrom"),
    ("sys_sendmsg", "trace_sys_sendmsg", "__x64_sys_sendmsg"),
    ("sys_recvmsg", "trace_sys_recvmsg", "__x64_sys_recvmsg"),
    ("sys_send", "trace_sys_send", "__x64_sys_send"),
    ("sys_recv", "trace_sys_recv", "__x64_sys_recv"),
]
KERNEL_PROBES = [
    ("tcp_sendmsg", "trace_tcp_sendmsg"),
    ("tcp_recvmsg", "trace_tcp_recvmsg"),
]


def main():
    parser = argparse.ArgumentParser(description="Plaintext IO path audit (count-only)")
    parser.add_argument("--pid", type=int, required=True, help="Target PID")
    parser.add_argument("--duration", type=int, default=30, help="Audit duration (seconds)")
    parser.add_argument("--output", type=str, default="", help="Output JSON path")
    args = parser.parse_args()

    if not HAS_BPF:
        print("[audit] ERROR: BCC not available")
        sys.exit(1)

    print(f"[audit] Target PID: {args.pid}, Duration: {args.duration}s")

    b = BPF(text=BPF_PROGRAM)

    # Set target PID
    target_key = ctypes.c_int(0)
    target_val = ctypes.c_uint32(args.pid)
    b["target_pid_map"][target_key] = target_val

    # Attach probes (best-effort)
    attached = []
    for name, fn, event in SYSCALL_PROBES:
        try:
            b.attach_kprobe(event=event, fn_name=fn)
            attached.append(name)
        except Exception:
            try:
                # Try fallback name (without __x64_ prefix)
                fallback = event.replace("__x64_", "")
                b.attach_kprobe(event=fallback, fn_name=fn)
                attached.append(name)
            except Exception:
                pass

    for event, fn in KERNEL_PROBES:
        try:
            b.attach_kprobe(event=event, fn_name=fn)
            attached.append(event)
        except Exception:
            pass

    print(f"[audit] Attached: {', '.join(attached)}")

    # Wait
    def handler(sig, frame):
        pass
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    time.sleep(args.duration)

    # Read counters
    result = {
        "target_pid": args.pid,
        "duration_sec": args.duration,
        "raw_payload_saved": False,
    }

    counters = b["counters"]
    for i, name in enumerate(COUNTER_NAMES):
        try:
            val = counters[ctypes.c_int(i)].value
        except Exception:
            val = 0
        result[name] = val

    # Summary
    total_send = sum(result.get(k, 0) for k in COUNTER_NAMES if "send" in k or "write" in k)
    total_recv = sum(result.get(k, 0) for k in COUNTER_NAMES if "recv" in k or "read" in k)
    result["total_send_events"] = total_send
    result["total_recv_events"] = total_recv

    # Find dominant path
    max_name = max(COUNTER_NAMES, key=lambda k: result.get(k, 0))
    result["dominant_path"] = max_name
    result["dominant_count"] = result.get(max_name, 0)

    print(f"[audit] Results:")
    for name in COUNTER_NAMES:
        val = result[name]
        marker = " <<<" if name == max_name and val > 0 else ""
        print(f"  {name}: {val}{marker}")
    print(f"  total_send: {total_send}, total_recv: {total_recv}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[audit] Output: {args.output}")


if __name__ == "__main__":
    main()
