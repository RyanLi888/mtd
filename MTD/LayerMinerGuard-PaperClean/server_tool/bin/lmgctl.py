#!/usr/bin/env python3
"""LayerMinerGuard control utility.

Usage:
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml status
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml alerts
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml observations
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml traffic-alerts
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml warnings
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml tail
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml stop
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml clear-alerts
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml clear-state
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml clear-warnings
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml clear-observations
    python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml clear-all
"""

import argparse
import glob
import json
import os
import sys
import time

_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from server_tool.layerminer_server.manual_agent import load_config
from server_tool.layerminer_server.alert_store import read_recent_alerts, read_recent_observations
from server_tool.layerminer_server import result_mirror


def _pid_file_path(config: dict) -> str:
    output_cfg = config.get("output", {})
    return output_cfg.get("pid_file", "results/layerminerd.pid")


def _daemon_log_path(config: dict) -> str:
    output_cfg = config.get("output", {})
    return output_cfg.get("daemon_log", "results/layerminerd.log")


def _read_pid(path: str) -> int:
    try:
        with open(path) as f:
            return int(f.read().strip() or "0")
    except (OSError, ValueError):
        return 0


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


def _find_layerminerd_pids(config: dict) -> list[int]:
    """Find running layerminerd processes even when the pid file is missing."""
    pids = []
    self_pid = os.getpid()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == self_pid:
            continue
        cmdline_path = os.path.join("/proc", name, "cmdline")
        try:
            with open(cmdline_path, "rb") as f:
                raw = f.read().replace(b"\x00", b" ").decode(errors="ignore")
        except (OSError, PermissionError):
            continue
        if "layerminerd.py" in raw and "server_tool/config/live.yaml" in raw:
            pids.append(pid)
    return sorted(set(pids))


def _candidate_state_path(config: dict) -> str:
    output_cfg = config.get("output", {})
    primary = output_cfg.get("candidate_state_json", "/var/lib/layerminer/candidate_state.json")
    fallback = "/tmp/layerminer/candidate_state.json"
    if os.path.exists(primary):
        return primary
    if os.path.exists(fallback):
        return fallback
    return primary


def _warning_log_path(config: dict) -> str:
    console_cfg = config.get("console", {})
    primary = console_cfg.get("warning_log", "/var/log/layerminer/warnings.log")
    fallback = "/tmp/layerminer/warnings.log"
    if os.path.exists(primary):
        return primary
    if os.path.exists(fallback):
        return fallback
    return primary


def _traffic_alerts_path(config: dict) -> str:
    cfg = config.get("traffic_alerts", {})
    return result_mirror.result_path(config, cfg.get("filename", "traffic_alerts.jsonl"))


def _read_jsonl(path: str, limit: int = 20) -> list[dict]:
    if not os.path.exists(path):
        return []
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except PermissionError:
        return []
    return rows[-limit:]


def cmd_status(config: dict):
    """Show status summary."""
    output_cfg = config.get("output", {})
    alerts_path = output_cfg.get("alerts_jsonl", "/var/log/layerminer/alerts.jsonl")
    fallback = "/tmp/layerminer/alerts.jsonl"
    path = alerts_path if os.path.exists(alerts_path) else fallback
    exists = os.path.exists(path)

    alerts = read_recent_alerts(config, limit=1000)
    count = len(alerts)

    agent_cfg = config.get("agent", {})
    cand_cfg = config.get("candidate", {})
    obs_cfg = config.get("observer", {})
    policy = config.get("alert_policy", {})

    state_path = _candidate_state_path(config)
    state_exists = os.path.exists(state_path)

    warn_path = _warning_log_path(config)
    warn_exists = os.path.exists(warn_path)
    warn_count = 0
    pid_file = _pid_file_path(config)
    daemon_log = _daemon_log_path(config)
    daemon_pid = _read_pid(pid_file)
    daemon_running = _pid_is_running(daemon_pid)
    detected_pids = _find_layerminerd_pids(config)
    if warn_exists:
        try:
            with open(warn_path) as f:
                warn_count = sum(1 for line in f if line.strip())
        except PermissionError:
            pass

    print("=== LayerMinerGuard Status ===")
    print(f"  Alerts file: {path}")
    print(f"  Alerts file exists: {exists}")
    print(f"  Total alerts: {count}")
    print(f"  Candidate state: {state_path}")
    print(f"  State file exists: {state_exists}")
    print(f"  Warnings file: {warn_path}")
    print(f"  Warnings file exists: {warn_exists}")
    print(f"  Total warnings: {warn_count}")
    traffic_path = _traffic_alerts_path(config)
    print(f"  Traffic alerts file: {traffic_path}")
    print(f"  Traffic alerts exists: {os.path.exists(traffic_path)}")
    print(f"  Results mirror: {result_mirror.result_dir(config)}")
    print(f"  Daemon pid file: {pid_file}")
    print(f"  Daemon pid: {daemon_pid or '-'}")
    print(f"  Daemon running: {daemon_running or bool(detected_pids)}")
    if detected_pids:
        print(f"  Detected daemon pids: {', '.join(str(p) for p in detected_pids)}")
    print(f"  Daemon log: {daemon_log}")
    print(f"  Background mode: {agent_cfg.get('background', False)}")
    print(f"  Mode: {agent_cfg.get('mode', 'manual')}")
    print(f"  Dry-run: {agent_cfg.get('dry_run', True)}")
    print(f"  Scan interval: {agent_cfg.get('scan_interval_sec', 10)}s")
    print(f"  Observe duration: {agent_cfg.get('observe_duration_sec', 120)}s")
    print(f"  Probe mode: {obs_cfg.get('probe_mode', 'on_demand')}")
    print(f"  Max candidates/scan: {cand_cfg.get('max_candidates_per_scan', 10)}")
    print(f"  Min consecutive hits: {cand_cfg.get('min_consecutive_hits', 3)}")
    print(f"  Ignore system services: {cand_cfg.get('ignore_system_services', True)}")
    print(f"  Emit confirmed alerts: {policy.get('emit_confirmed_alerts', True)}")
    print(f"  Emit suspicious alerts: {policy.get('emit_protocol_suspicious_alerts', False)}")

    # Show last confirmed alert if available
    recent = read_recent_alerts(config, limit=1)
    if recent:
        last = recent[0]
        ev = last.get("evidence", {})
        print()
        print("  Last confirmed alert:")
        print(f"    time: {last.get('timestamp', '?')}")
        print(f"    host: {last.get('host', '?')}")
        print(f"    pid: {last.get('pid', '?')}")
        print(f"    process: {last.get('process_name', '?')}")
        print(f"    verdict: {last.get('verdict', '?')}")
        print(f"    severity: {last.get('severity', '?')}")
        print(f"    confidence: {last.get('confidence', '?')}")
        print(f"    visibility: {last.get('visibility_mode', '?')}")
        print(f"    evidence: job={ev.get('job_marker_count', 0)} "
              f"submit={ev.get('submit_marker_count', 0)} "
              f"assoc={ev.get('associated_submit_count', 0)}")
        print(f"    action: {last.get('recommended_action', '?')}")


def cmd_alerts(config: dict):
    """Show recent formal alerts."""
    alerts = read_recent_alerts(config, limit=20)
    if not alerts:
        print("No alerts found.")
        return

    print(f"=== Recent {len(alerts)} Alerts ===")
    for i, alert in enumerate(alerts, 1):
        ts = alert.get("timestamp", "?")
        run_id = alert.get("run_id", "?")
        host = alert.get("host", "?")
        pid = alert.get("pid", "?")
        name = alert.get("process_name", "?")
        verdict = alert.get("verdict", "?")
        severity = alert.get("severity", "")
        confidence = alert.get("confidence", "")
        vis = alert.get("visibility_mode", "")
        rec = alert.get("recommended_action", "")

        evidence = alert.get("evidence", {})
        j = evidence.get("job_marker_count", 0)
        s = evidence.get("submit_marker_count", 0)
        a = evidence.get("associated_submit_count", 0)

        print(f"  {i}. [{run_id}] {ts}")
        print(f"     host={host} pid={pid} name={name}")
        print(f"     verdict={verdict} severity={severity} confidence={confidence}")
        print(f"     visibility={vis} job={j} submit={s} assoc={a}")
        print(f"     action={rec}")


def cmd_observations(config: dict):
    """Show recent observation records."""
    records = read_recent_observations(config, limit=10)
    if not records:
        print("No observation records found.")
        return

    print(f"=== Recent {len(records)} Observations ===")
    for i, rec in enumerate(records, 1):
        ts = rec.get("timestamp", "?")
        run_id = rec.get("run_id", "?")
        pid = rec.get("pid", "?")
        name = rec.get("process_name", "?")
        verdict = rec.get("verdict", "?")
        confidence = rec.get("confidence", "")
        reasons = rec.get("reasons", [])

        evidence = rec.get("evidence", {})
        j = evidence.get("job_marker_count", 0)
        s = evidence.get("submit_marker_count", 0)
        a = evidence.get("associated_submit_count", 0)
        cpu = evidence.get("cpu_avg_percent", 0)

        print(f"  {i}. [{run_id}] {ts} pid={pid} name={name}")
        print(f"     verdict={verdict} confidence={confidence} cpu={cpu}%")
        print(f"     job={j} submit={s} assoc={a}")
        if reasons:
            print(f"     reasons: {', '.join(reasons)}")


def cmd_traffic_alerts(config: dict):
    """Show recent abnormal traffic correlation records."""
    path = _traffic_alerts_path(config)
    records = _read_jsonl(path, limit=20)
    if not records:
        print(f"No traffic alerts found at {path}.")
        return
    print(f"=== Recent {len(records)} Traffic Alerts ===")
    for i, rec in enumerate(records, 1):
        ts = rec.get("timestamp", "?")
        server = rec.get("server", "?")
        src = rec.get("src_ip", "") or "[hidden]"
        dst = rec.get("dst_ip", "") or "[hidden]"
        port = rec.get("dst_port", 0) or "?"
        proto = rec.get("protocol", "?")
        proc = rec.get("process", "?")
        pid = rec.get("pid", "?")
        level = rec.get("level", "?")
        verdict = rec.get("verdict", "?")
        ev = rec.get("evidence", {})
        print(f"{i}. {ts} server={server} {src} -> {dst}:{port}/{proto} pid={pid} process={proc} level={level} verdict={verdict}")
        print(f"   evidence: job={ev.get('job_marker_count', 0)} submit={ev.get('submit_marker_count', 0)} assoc={ev.get('associated_submit_count', 0)}")
        print(f"   correlation_id={rec.get('traffic_correlation_id', '')}")


def cmd_warnings(config: dict):
    """Show recent warning lines."""
    warn_path = _warning_log_path(config)
    if not os.path.exists(warn_path):
        print(f"No warnings file found at {warn_path}.")
        return
    try:
        with open(warn_path) as f:
            lines = [line.strip() for line in f if line.strip()]
    except PermissionError:
        print(f"Permission denied reading {warn_path}")
        return
    if not lines:
        print("No warnings found.")
        return
    recent = lines[-20:]
    print(f"=== Recent {len(recent)} Warnings ===")
    for line in recent:
        print(f"  {line}")


def cmd_clear_alerts(config: dict):
    """Clear all alerts."""
    output_cfg = config.get("output", {})
    alerts_path = output_cfg.get("alerts_jsonl", "/var/log/layerminer/alerts.jsonl")
    fallback = "/tmp/layerminer/alerts.jsonl"
    path = alerts_path if os.path.exists(alerts_path) else fallback

    if os.path.exists(path):
        try:
            with open(path) as f:
                count = sum(1 for line in f if line.strip())
        except PermissionError:
            print(f"Permission denied reading {path}")
            count = None
        if count is not None:
            try:
                with open(path, 'w') as f:
                    pass
                print(f"Cleared {count} alerts from {path}")
            except PermissionError:
                print(f"Permission denied writing {path}. Try with sudo.")
    else:
        print(f"No alerts file found at {path}. Nothing to clear.")

    mirror_count = result_mirror.clear_file(config, "alerts.jsonl")
    if mirror_count:
        print(f"Cleared {mirror_count} mirrored alerts from {result_mirror.result_path(config, 'alerts.jsonl')}")
    traffic_count = result_mirror.clear_file(config, config.get("traffic_alerts", {}).get("filename", "traffic_alerts.jsonl"))
    if traffic_count:
        print(f"Cleared {traffic_count} traffic alerts from {_traffic_alerts_path(config)}")


def cmd_clear_state(config: dict):
    """Clear candidate state file."""
    state_path = _candidate_state_path(config)
    if os.path.exists(state_path):
        try:
            with open(state_path) as f:
                state = json.load(f)
            count = len(state)
        except (json.JSONDecodeError, PermissionError):
            count = "?"
        try:
            with open(state_path, 'w') as f:
                json.dump({}, f)
            print(f"Cleared {count} candidate records from {state_path}")
        except PermissionError:
            print(f"Permission denied writing {state_path}. Try with sudo.")
    else:
        print(f"No state file found at {state_path}. Nothing to clear.")

    mirror_count = result_mirror.clear_json_file(config, "candidate_state.json")
    if mirror_count:
        path = result_mirror.result_path(config, "candidate_state.json")
        print(f"Cleared {mirror_count} mirrored candidate records from {path}")


def cmd_clear_warnings(config: dict):
    """Clear warnings log."""
    warn_path = _warning_log_path(config)
    if os.path.exists(warn_path):
        try:
            with open(warn_path) as f:
                count = sum(1 for line in f if line.strip())
        except PermissionError:
            print(f"Permission denied reading {warn_path}")
            count = None
        if count is not None:
            try:
                with open(warn_path, 'w') as f:
                    pass
                print(f"Cleared {count} warning lines from {warn_path}")
            except PermissionError:
                print(f"Permission denied writing {warn_path}. Try with sudo.")
    else:
        print(f"No warnings file found at {warn_path}. Nothing to clear.")

    mirror_count = result_mirror.clear_file(config, "warnings.log")
    if mirror_count:
        print(f"Cleared {mirror_count} mirrored warning lines from {result_mirror.result_path(config, 'warnings.log')}")


def cmd_clear_observations(config: dict):
    """Clear observation records and temp probe outputs."""
    output_cfg = config.get("output", {})
    obs_dir = output_cfg.get("observation_dir", "/var/log/layerminer/observations")
    fallback_dir = "/tmp/layerminer/observations"

    total = 0
    for directory in [obs_dir, fallback_dir]:
        if os.path.isdir(directory):
            for fname in os.listdir(directory):
                if fname.endswith(".json") and not fname.startswith("."):
                    fpath = os.path.join(directory, fname)
                    try:
                        os.remove(fpath)
                        total += 1
                    except PermissionError:
                        print(f"Permission denied removing {fpath}")

    # Clean /tmp/lmg_obs_* directories
    for d in glob.glob("/tmp/lmg_obs_*"):
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    os.remove(os.path.join(d, f))
                os.rmdir(d)
                total += 1
            except (PermissionError, OSError):
                pass

    mirror_total = result_mirror.clear_observations(config)
    random_total = result_mirror.clear_json_dir(config, "random_observations")
    print(f"Cleared {total} observation files")
    if mirror_total:
        print(f"Cleared {mirror_total} mirrored observation files")
    if random_total:
        print(f"Cleared {random_total} random observation files")


def cmd_clear_all(config: dict):
    """Clear all: alerts, state, warnings, observations."""
    print("Clear-all completed:")
    cmd_clear_alerts(config)
    cmd_clear_state(config)
    cmd_clear_warnings(config)
    cmd_clear_observations(config)


def cmd_stop(config: dict):
    """Stop the background daemon by pid file or process scan."""
    pid_file = _pid_file_path(config)
    pid = _read_pid(pid_file)
    pids = []
    if _pid_is_running(pid):
        pids.append(pid)
    for detected in _find_layerminerd_pids(config):
        if detected not in pids:
            pids.append(detected)

    if not pids:
        print(f"No running layerminerd daemon found from {pid_file}.")
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
                print(f"Removed stale pid file: {pid_file}")
            except PermissionError:
                print(f"Permission denied removing stale pid file: {pid_file}")
        return

    stopped = []
    for target_pid in pids:
        try:
            os.kill(target_pid, 15)
            stopped.append(target_pid)
        except PermissionError:
            print(f"Permission denied stopping pid={target_pid}. Try with sudo.")
        except ProcessLookupError:
            pass

    for _ in range(30):
        time.sleep(0.2)
        if all(not _pid_is_running(target_pid) for target_pid in stopped):
            break

    for target_pid in stopped:
        if _pid_is_running(target_pid):
            print(f"Sent SIGTERM to layerminerd daemon pid={target_pid}; it may still be shutting down.")
        else:
            print(f"Stopped layerminerd daemon pid={target_pid}")

    if os.path.exists(pid_file):
        try:
            os.remove(pid_file)
        except OSError:
            pass


def cmd_tail(config: dict):
    """Continuously tail alerts.jsonl."""
    output_cfg = config.get("output", {})
    alerts_path = output_cfg.get("alerts_jsonl", "/var/log/layerminer/alerts.jsonl")
    fallback = "/tmp/layerminer/alerts.jsonl"
    path = alerts_path if os.path.exists(alerts_path) else fallback
    if not os.path.exists(path):
        print(f"Alerts file does not exist: {path}")
        print("Waiting for first alert...")
        while not os.path.exists(path):
            time.sleep(1)
    print(f"Tailing {path} (Ctrl+C to stop)")
    try:
        with open(path) as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    try:
                        alert = json.loads(line.strip())
                        ts = alert.get("timestamp", "?")
                        run_id = alert.get("run_id", "?")
                        pid = alert.get("pid", "?")
                        name = alert.get("process_name", "?")
                        verdict = alert.get("verdict", "?")
                        print(f"[{run_id}] [{ts}] pid={pid} name={name} verdict={verdict}")
                    except json.JSONDecodeError:
                        print(line.strip())
                else:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopped tailing.")


def main():
    parser = argparse.ArgumentParser(description="LayerMinerGuard control utility")
    parser.add_argument("--config", type=str, required=True, help="Path to config YAML")
    parser.add_argument("command", choices=[
        "status", "alerts", "observations", "traffic-alerts", "warnings", "tail", "stop",
        "clear-alerts", "clear-state", "clear-warnings", "clear-observations", "clear-all"
    ], help="Command to execute")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.command == "status":
        cmd_status(config)
    elif args.command == "alerts":
        cmd_alerts(config)
    elif args.command == "observations":
        cmd_observations(config)
    elif args.command == "traffic-alerts":
        cmd_traffic_alerts(config)
    elif args.command == "warnings":
        cmd_warnings(config)
    elif args.command == "tail":
        cmd_tail(config)
    elif args.command == "stop":
        cmd_stop(config)
    elif args.command == "clear-alerts":
        cmd_clear_alerts(config)
    elif args.command == "clear-state":
        cmd_clear_state(config)
    elif args.command == "clear-warnings":
        cmd_clear_warnings(config)
    elif args.command == "clear-observations":
        cmd_clear_observations(config)
    elif args.command == "clear-all":
        cmd_clear_all(config)


if __name__ == "__main__":
    main()
