#!/usr/bin/env python3
"""Process cleanup utility.

Kills all mining-related processes safely. Used by runners and as standalone.
"""

import os
import signal
import subprocess
import sys
import time


PATTERNS = [
    "xmrig",
    "fake_stratum",
    "fake_pool",
    "bcc_tls_uprobe",
    "bcc_stratum",
    "p21_target_network",
    "p21_process_telemetry",
    "p21_compute_behavioral",
    "p21_finalize",
    "p21_launch_suspended",
]


def find_matching_pids(patterns: list[str]) -> list[int]:
    """Find PIDs matching any of the patterns."""
    pids = []
    for pattern in patterns:
        try:
            result = subprocess.run(
                ["pgrep", "-f", pattern],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        pid = int(line.strip())
                        if pid != os.getpid():  # Don't kill ourselves
                            pids.append(pid)
                    except ValueError:
                        pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return list(set(pids))


def kill_process(pid: int, force: bool = False) -> bool:
    """Kill a process by PID. Returns True if successful."""
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.kill(pid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return True  # Already dead or no permission


def cleanup_all(max_attempts: int = 3, verbose: bool = True) -> list[int]:
    """Kill all matching processes. Returns list of residual PIDs."""
    for attempt in range(max_attempts):
        pids = find_matching_pids(PATTERNS)
        if not pids:
            if verbose:
                print(f"[cleanup] No matching processes (attempt {attempt + 1})")
            return []

        if verbose:
            print(f"[cleanup] Found {len(pids)} processes (attempt {attempt + 1})")

        # SIGTERM first
        for pid in pids:
            kill_process(pid, force=False)
        time.sleep(3)

        # SIGKILL remaining
        remaining = find_matching_pids(PATTERNS)
        for pid in remaining:
            kill_process(pid, force=True)
        time.sleep(2)

    # Final check
    residual = find_matching_pids(PATTERNS)
    if verbose and residual:
        print(f"[cleanup] WARNING: {len(residual)} residual processes: {residual}")
    elif verbose:
        print("[cleanup] All processes cleaned")

    return residual


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cleanup mining-related processes")
    parser.add_argument("--max-attempts", type=int, default=3, help="Max cleanup attempts")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    args = parser.parse_args()

    residual = cleanup_all(max_attempts=args.max_attempts, verbose=not args.quiet)
    sys.exit(1 if residual else 0)


if __name__ == "__main__":
    main()
