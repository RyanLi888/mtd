#!/usr/bin/env python3
"""LayerMinerGuard server daemon — manual detection agent.

Supports dry-run and live detection modes.

Usage:
    # Dry-run (no root required)
    python3 server_tool/bin/layerminerd.py --config server_tool/config/server.yaml --once

    # Live detection (requires root)
    sudo python3 server_tool/bin/layerminerd.py --config server_tool/config/live.yaml --once
    sudo python3 server_tool/bin/layerminerd.py --config server_tool/config/live.yaml
"""

import argparse
import atexit
import os
import signal
import sys

# Ensure project root is on sys.path for imports
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from server_tool.layerminer_server.manual_agent import load_config, run_once, run_loop


def _prepare_output_path(primary: str, fallback: str) -> str:
    """Return a writable output path, falling back when needed."""
    parent = os.path.dirname(primary)
    try:
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(primary, "a"):
            pass
        return primary
    except PermissionError:
        fallback_parent = os.path.dirname(fallback)
        if fallback_parent:
            os.makedirs(fallback_parent, exist_ok=True)
        return fallback


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _read_pid(pid_file: str) -> int:
    try:
        with open(pid_file) as f:
            return int(f.read().strip() or "0")
    except (OSError, ValueError):
        return 0


def _install_pid_cleanup(pid_file: str) -> None:
    def cleanup() -> None:
        try:
            if _read_pid(pid_file) == os.getpid():
                os.remove(pid_file)
        except OSError:
            pass

    def handle_signal(signum, frame) -> None:
        cleanup()
        sys.exit(0)

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)


def _daemonize(config: dict) -> None:
    """Fork the current process into the background and redirect logs."""
    output_cfg = config.get("output", {})
    pid_file = output_cfg.get("pid_file", "results/layerminerd.pid")
    daemon_log = output_cfg.get("daemon_log", "results/layerminerd.log")
    pid_file = _prepare_output_path(pid_file, "/tmp/layerminer/layerminerd.pid")
    daemon_log = _prepare_output_path(daemon_log, "/tmp/layerminer/layerminerd.log")

    existing_pid = _read_pid(pid_file)
    if _pid_is_running(existing_pid):
        print(f"[layerminerd] already running in background: pid={existing_pid}")
        print(f"[layerminerd] pid_file={pid_file}")
        print(f"[layerminerd] log={daemon_log}")
        sys.exit(0)

    pid = os.fork()
    if pid > 0:
        print(f"[layerminerd] started in background: pid={pid}")
        print(f"[layerminerd] pid_file={pid_file}")
        print(f"[layerminerd] log={daemon_log}")
        sys.exit(0)

    os.setsid()
    sys.stdin.flush()
    sys.stdout.flush()
    sys.stderr.flush()

    with open(os.devnull, "r") as stdin, open(daemon_log, "a", buffering=1) as log:
        os.dup2(stdin.fileno(), sys.stdin.fileno())
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())

    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    _install_pid_cleanup(pid_file)
    print(f"[layerminerd] background worker running: pid={os.getpid()}", flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="LayerMinerGuard manual server agent"
    )
    parser.add_argument(
        "--config", type=str, required=True,
        help="Path to configuration YAML file"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run one scan cycle and exit"
    )
    parser.add_argument(
        "--foreground", action="store_true",
        help="Run in the foreground even if config enables background mode"
    )
    parser.add_argument(
        "--background", action="store_true",
        help="Force background mode for continuous monitoring"
    )
    args = parser.parse_args()

    config = load_config(args.config)
    agent_cfg = config.get("agent", {})
    dry_run = agent_cfg.get("dry_run", True)

    # Root check for live mode
    if not dry_run and os.geteuid() != 0:
        print("[layerminerd] ERROR: live detection mode requires root.")
        print("[layerminerd] Please run with: sudo python3 ...")
        sys.exit(1)

    if dry_run and os.geteuid() != 0:
        print("[layerminerd] WARNING: dry-run mode without root, some process info may be limited")

    background = args.background or (agent_cfg.get("background", False) and not args.foreground)

    if args.once:
        summary = run_once(config)
        import json
        print(json.dumps(summary, indent=2))
    else:
        if background:
            _daemonize(config)
        run_loop(config)


if __name__ == "__main__":
    main()
