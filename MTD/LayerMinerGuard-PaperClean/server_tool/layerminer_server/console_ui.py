"""Console UI for LayerMinerGuard server tool.

Provides startup banner, scan summaries, and mining warnings.
Never prints raw payload, wallet, job_id, nonce, result, blob, or full cmdline.
"""

import os
import time
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

from . import result_mirror


def _display_tz(config: dict):
    """Return configured display timezone; UTC fallback keeps logs explicit."""
    tz_name = config.get("console", {}).get("display_timezone", "UTC")
    if ZoneInfo:
        try:
            return ZoneInfo(tz_name), tz_name
        except Exception:
            pass
    return timezone.utc, "UTC"


def format_display_time(config: dict) -> str:
    """Format current time for human-facing logs."""
    tz, tz_name = _display_tz(config)
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S") + f" {tz_name}"



def print_startup_banner(config: dict) -> None:
    """Print startup banner with configuration summary."""
    agent = config.get("agent", {})
    obs = config.get("observer", {})
    output = config.get("output", {})
    policy = config.get("alert_policy", {})
    console = config.get("console", {})

    mode = agent.get("mode", "manual")
    probe_mode = obs.get("probe_mode", "on_demand")
    interval = agent.get("scan_interval_sec", 10)
    observe_dur = agent.get("observe_duration_sec", 300)
    alerts_path = output.get("alerts_jsonl", "/var/log/layerminer/alerts.jsonl")
    obs_dir = output.get("observation_dir", "/var/log/layerminer/observations")
    result_dir = output.get("result_dir", "results")
    action = agent.get("default_action", "alert_only")
    auto_kill = "enabled" if action == "kill" else "disabled"
    auto_start = "enabled" if agent.get("auto_start", False) else "disabled"
    warn_log = console.get("warning_log", "/var/log/layerminer/warnings.log")
    _, display_tz_name = _display_tz(config)

    print("=" * 60)
    print(" LayerMinerGuard Manual Live Server Agent")
    print("=" * 60)
    print(f" {'Mode':<20}: {mode}")
    print(f" {'Probe mode':<20}: {probe_mode}")
    print(f" {'Scan interval':<20}: {interval}s")
    print(f" {'Display timezone':<20}: {display_tz_name}")
    print(f" {'Observe window':<20}: {observe_dur}s")
    print(f" {'Formal alerts':<20}: {alerts_path}")
    print(f" {'Observations':<20}: {obs_dir}")
    print(f" {'Warning log':<20}: {warn_log}")
    print(f" {'Results mirror':<20}: {result_dir}")
    print(f" {'Mirror alerts':<20}: {os.path.join(result_dir, 'alerts.jsonl')}")
    print(f" {'Mirror obs':<20}: {os.path.join(result_dir, 'observations')}")
    print(f" {'Mirror warnings':<20}: {os.path.join(result_dir, 'warnings.log')}")
    print(f" {'Auto kill':<20}: {auto_kill}")
    print(f" {'Auto start':<20}: {auto_start}")
    print(f" {'Emit confirmed':<20}: {policy.get('emit_confirmed_alerts', True)}")
    print(f" {'Emit suspicious':<20}: {policy.get('emit_protocol_suspicious_alerts', False)}")
    print(f" {'Privacy':<20}: raw payload / wallet / job_id / nonce not saved")
    print("=" * 60)
    print("[agent] Live detection started. Press Ctrl+C to stop.")
    print()


def print_scan_summary(summary: dict, config: dict = None) -> None:
    """Print concise one-line scan summary."""
    ts = format_display_time(config or {})
    run_id = summary.get("run_id", "?")[:8]
    raw = summary.get("raw_candidate_count", 0)
    eligible = summary.get("observation_eligible_count", 0)
    weak = summary.get("weak_candidate_count", 0)
    confirmed = summary.get("confirmed_candidate_count", 0)
    pending = summary.get("pending_candidate_count", 0)
    observed = summary.get("observed_count", 0)
    obs_written = summary.get("observations_written", 0)
    alerts = summary.get("confirmed_alerts_written", 0)
    mining = summary.get("confirmed_mining_count", 0)
    suspicious = summary.get("protocol_suspicious_count", 0) + summary.get("fallback_suspicious_count", 0)
    last_alert = summary.get("last_alert_verdict", "")
    last_pid = summary.get("last_alert_pid", 0)

    parts = [
        f"[{ts}]",
        f"run={run_id}",
        f"raw={raw}",
        f"eligible={eligible}",
        f"weak={weak}",
        f"confirmed={confirmed}",
        f"pending={pending}",
        f"observed={observed}",
        f"obs={obs_written}",
        f"alerts={alerts}",
    ]
    if mining > 0:
        parts.append(f"mining={mining}")
    if suspicious > 0:
        parts.append(f"suspicious={suspicious}")
    if last_alert:
        parts.append(f"last_alert={last_alert} pid={last_pid}")

    print(" ".join(parts))


def format_warning_line(alert: dict, alert_path: str = "") -> str:
    """Format a single-line sanitized warning for logging.

    Args:
        alert: Confirmed alert dict.
        alert_path: Path to alerts file.

    Returns:
        One-line sanitized text.
    """
    ts = alert.get("timestamp", datetime.now(timezone.utc).isoformat())
    ev = alert.get("evidence", {})
    vis = alert.get("visibility_mode", "")
    obs_info = alert.get("observation", {})
    early = obs_info.get("early_confirmed", False)
    actual_dur = obs_info.get("actual_observe_duration_sec", 0)

    parts = [
        ts,
        f"verdict={alert.get('verdict', '?')}",
        f"severity={alert.get('severity', '?')}",
        f"pid={alert.get('pid', '?')}",
        f"process={alert.get('process_name', '?')}",
        f"user={alert.get('process_user', '?')}",
        f"visibility={vis}",
        f"job={ev.get('job_marker_count', 0)}",
        f"submit={ev.get('submit_marker_count', 0)}",
        f"assoc={ev.get('associated_submit_count', 0)}",
        f"action={alert.get('recommended_action', '?')}",
    ]
    if early:
        parts.append(f"early_confirmed=true actual_duration={actual_dur}s")
    if alert_path:
        parts.append(f"alert_json={alert_path}")
    return " ".join(parts)


def append_warning_log(alert: dict, config: dict, alert_path: str = "") -> str:
    """Append a sanitized warning line to warnings.log.

    Args:
        alert: Confirmed alert dict.
        config: Configuration dict.
        alert_path: Path to alerts file.

    Returns:
        Path to warnings.log.
    """
    console_cfg = config.get("console", {})
    primary = console_cfg.get("warning_log", "/var/log/layerminer/warnings.log")
    fallback = "/tmp/layerminer/warnings.log"

    path = primary
    parent = os.path.dirname(primary)
    try:
        os.makedirs(parent, exist_ok=True)
        with open(primary, 'a') as f:
            pass
    except PermissionError:
        path = fallback
        os.makedirs(os.path.dirname(fallback), exist_ok=True)

    line = format_warning_line(alert, alert_path)
    with open(path, 'a') as f:
        f.write(line + "\n")
    result_mirror.append_line(config, "warnings.log", line)

    return path


def print_confirmed_warning(alert: dict, alert_path: str = "", config: dict = None) -> None:
    """Print prominent WARNING for confirmed mining with repeat and bell.

    Args:
        alert: Confirmed alert dict.
        alert_path: Path to alerts file.
        config: Configuration dict (for repeat/bell settings).
    """
    console_cfg = config.get("console", {}) if config else {}
    repeat_count = console_cfg.get("alert_repeat_count", 3)
    repeat_interval = console_cfg.get("alert_repeat_interval_sec", 1)
    terminal_bell = console_cfg.get("terminal_bell", True)

    ev = alert.get("evidence", {})
    vis = alert.get("visibility_mode", "")
    boundary = alert.get("visibility_boundary", "")

    for i in range(repeat_count):
        if terminal_bell:
            print("\a", end="", flush=True)
        print()
        print("=" * 56)
        print(f" MINING WARNING {i + 1}/{repeat_count}")
        print("=" * 56)
        print(f" {'Verdict':<16}: {alert.get('verdict', '?')}")
        print(f" {'Severity':<16}: {alert.get('severity', '?')}")
        print(f" {'PID':<16}: {alert.get('pid', '?')}")
        print(f" {'Process':<16}: {alert.get('process_name', '?')}")
        print(f" {'User':<16}: {alert.get('process_user', '?')}")
        print(f" {'CPU avg':<16}: {ev.get('cpu_avg_percent', 0)}%")
        print(f" {'Visibility':<16}: {vis}")
        if boundary:
            print(f" {'Boundary':<16}: {boundary}")
        print(f" {'Evidence':<16}: job={ev.get('job_marker_count', 0)} "
              f"submit={ev.get('submit_marker_count', 0)} "
              f"assoc={ev.get('associated_submit_count', 0)}")
        obs_info = alert.get("observation", {})
        if obs_info.get("early_confirmed", False):
            actual = obs_info.get("actual_observe_duration_sec", 0)
            planned = obs_info.get("observe_duration_sec", 0)
            print(f" {'Early confirm':<16}: true")
            print(f" {'Observe used':<16}: {actual}s / {planned}s")
        if alert_path:
            print(f" {'Alert JSON':<16}: {alert_path}")
        print(f" {'Action':<16}: {alert.get('recommended_action', '?')}")
        print("=" * 56)
        if i < repeat_count - 1:
            time.sleep(repeat_interval)


def print_observation_notice(record: dict, record_path: str = "") -> None:
    """Print one-line notice for non-confirmed observations."""
    ev = record.get("evidence", {})
    vis = record.get("visibility_mode", "")
    boundary = record.get("visibility_boundary", "")

    parts = [
        "[observation]",
        f"pid={record.get('pid', '?')}",
        f"process={record.get('process_name', '?')}",
        f"verdict={record.get('verdict', '?')}",
        f"confidence={record.get('confidence', '?')}",
        f"job={ev.get('job_marker_count', 0)}",
        f"submit={ev.get('submit_marker_count', 0)}",
        f"assoc={ev.get('associated_submit_count', 0)}",
    ]
    if vis:
        parts.append(f"vis={vis}")
    if boundary:
        parts.append(f"boundary={boundary}")
    if record_path:
        parts.append(f"record={record_path}")

    print(" ".join(parts))


def print_observation_skip(observation: dict) -> None:
    """Print notice for skipped observation (stale PID)."""
    pid = observation.get("pid", "?")
    name = observation.get("process_name", "?")
    reason = observation.get("skip_reason", "unknown")
    print(f"[skip] stale candidate pid={pid} process={name} reason={reason}")
