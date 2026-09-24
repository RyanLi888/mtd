"""Manual agent for LayerMinerGuard server tool.

Supports both dry-run and live detection modes.
dry_run=true: scan -> select -> state -> plan (no probes)
dry_run=false: scan -> select -> state -> observe -> verdict -> alert
"""

import os
import sys
import time
import uuid
import yaml

from .process_scanner import scan_processes
from .candidate_selector import select_candidates
from .candidate_state import update_candidate_state, load_candidate_state
from .observer_scheduler import build_observation_plan, should_observe_now, record_observation
from .alert_store import write_alert, write_observation_record, read_recent_alerts
from .json_schema import build_confirmed_alert, build_observation_record
from .console_ui import format_display_time, print_startup_banner, print_scan_summary
from .console_ui import print_confirmed_warning, print_observation_notice, print_observation_skip
from .console_ui import append_warning_log
from .random_observer import (
    random_observer_enabled,
    random_observer_interval,
    run_random_observation,
)
from .traffic_alert_store import (
    build_traffic_alert,
    has_abnormal_traffic_evidence,
    traffic_alerts_enabled,
    write_traffic_alert,
)


def load_config(path: str) -> dict:
    """Load configuration from YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def run_once(config: dict, observation_state: dict = None) -> dict:
    """Run one scan-select-confirm-observe-alert cycle.

    Args:
        config: Configuration dict.
        observation_state: Mutable dict tracking observation cooldowns.

    Returns:
        Summary dict with scan results.
    """
    if observation_state is None:
        observation_state = {}

    errors = []
    agent_cfg = config.get("agent", {})
    dry_run = agent_cfg.get("dry_run", True)
    run_id = uuid.uuid4().hex[:12]

    cand_cfg = config.get("candidate", {})
    min_hits = cand_cfg.get("min_consecutive_hits", 3)
    max_cand = cand_cfg.get("max_candidates_per_scan", 10)
    max_obs = agent_cfg.get("max_runtime_observations_per_loop", 1)

    policy = config.get("alert_policy", {})
    emit_confirmed = policy.get("emit_confirmed_alerts", True)
    emit_suspicious = policy.get("emit_protocol_suspicious_alerts", False)
    emit_fallback = policy.get("emit_fallback_suspicious_alerts", False)
    write_all_obs = policy.get("write_all_observations", True)

    # Root check for live mode
    if not dry_run and os.geteuid() != 0:
        errors.append("non_dry_run_requires_root")
        return {
            "run_id": run_id, "mode": agent_cfg.get("mode", "manual"),
            "dry_run": dry_run, "process_count": 0, "raw_candidate_count": 0,
            "confirmed_candidate_count": 0, "pending_candidate_count": 0,
            "suppressed_candidate_count": 0, "min_consecutive_hits": min_hits,
            "state_path": "", "top_candidates": [], "pending_candidates": [],
            "observed_count": 0, "observations_written": 0,
            "confirmed_alerts_written": 0, "suppressed_suspicious_alerts": 0,
            "skipped_observation_count": 0,
            "observation_eligible_count": 0, "weak_candidate_count": 0,
            "confirmed_mining_count": 0, "protocol_suspicious_count": 0,
            "fallback_suspicious_count": 0, "alerts_path": "",
            "scanner_warning": "", "errors": errors,
        }

    # Warning for dry-run without root
    if dry_run and os.geteuid() != 0:
        errors.append("warning: running without root, some process info may be limited")

    # Scan
    try:
        processes = scan_processes(config)
    except Exception as e:
        errors.append(f"scan_error: {e}")
        processes = []

    # Select candidates
    try:
        candidates = select_candidates(processes, config)
    except Exception as e:
        errors.append(f"select_error: {e}")
        candidates = []

    # Estimate suppressed count
    suppressed_count = 0
    try:
        uncapped_cfg = dict(config)
        uncapped_cfg["candidate"] = dict(cand_cfg, max_candidates_per_scan=999999)
        uncapped = select_candidates(processes, uncapped_cfg)
        suppressed_count = max(0, len(uncapped) - len(candidates))
    except Exception:
        pass

    # Update candidate state
    try:
        confirmed, pending, state = update_candidate_state(candidates, config)
    except Exception as e:
        errors.append(f"state_error: {e}")
        confirmed, pending, state = [], [], {}

    # Scanner warning
    scanner_warning = ""
    if not processes:
        scanner_warning = "no processes scanned"
    elif os.geteuid() != 0:
        scanner_warning = "running without root, some process info may be limited"

    # Live observation + verdict
    observed_count = 0
    observations_written = 0
    confirmed_alerts_written = 0
    suppressed_suspicious_alerts = 0
    skipped_observation_count = 0
    observation_eligible_count = 0
    weak_candidate_count = 0
    confirmed_mining_count = 0
    protocol_suspicious_count = 0
    fallback_suspicious_count = 0
    alerts_path = ""
    last_alert_verdict = ""
    last_alert_pid = 0
    last_alert_process = ""
    warning_log_path = ""

    # Count eligible vs weak from candidates
    for cand in candidates:
        if cand.get("observation_eligible", False):
            observation_eligible_count += 1
        else:
            weak_candidate_count += 1

    if not dry_run:
        from .live_observer import observe_candidate_live
        from .live_verdict import decide_live_verdict

        for cand in confirmed:
            if observed_count >= max_obs:
                break

            if not should_observe_now(cand, config, observation_state):
                continue

            try:
                observation = observe_candidate_live(cand, config)

                # Handle skipped observations (stale PID)
                if observation.get("observe_skipped", False):
                    skipped_observation_count += 1
                    print_observation_skip(observation)
                    continue

                verdict = decide_live_verdict(observation, config)
                record_observation(cand, verdict, observation_state)
                observed_count += 1

                v = verdict.get("verdict", "")
                if v == "confirmed_mining_live":
                    confirmed_mining_count += 1
                elif v == "protocol_suspicious":
                    protocol_suspicious_count += 1
                elif v == "fallback_suspicious":
                    fallback_suspicious_count += 1

                # Always write observation record if configured
                obs_path = ""
                if write_all_obs and v != "benign_or_unconfirmed":
                    try:
                        obs_record = build_observation_record(
                            cand, observation, verdict, config, run_id)
                        obs_path = write_observation_record(obs_record, config)
                        observations_written += 1
                    except Exception as e:
                        errors.append(f"obs_write_error pid={cand.get('pid')}: {e}")

                # Write formal alert based on policy
                should_alert = False
                if v == "confirmed_mining_live" and emit_confirmed:
                    should_alert = True
                elif v == "protocol_suspicious" and emit_suspicious:
                    should_alert = True
                elif v == "fallback_suspicious" and emit_fallback:
                    should_alert = True

                formal_alert_path = ""
                if should_alert:
                    alert = build_confirmed_alert(
                        cand, observation, verdict, config, run_id)
                    path = write_alert(alert, config)
                    formal_alert_path = path
                    alerts_path = path
                    confirmed_alerts_written += 1
                    # Track last alert
                    last_alert_verdict = alert.get("verdict", "")
                    last_alert_pid = alert.get("pid", 0)
                    last_alert_process = alert.get("process_name", "")
                    # Write warning log and print repeated warning
                    warning_log_path = append_warning_log(alert, config, path)
                    print_confirmed_warning(alert, path, config)
                else:
                    if v in ("protocol_suspicious", "fallback_suspicious"):
                        suppressed_suspicious_alerts += 1
                        if obs_path:
                            print_observation_notice(obs_record, obs_path)

                if traffic_alerts_enabled(config) and has_abnormal_traffic_evidence(observation, verdict):
                    try:
                        traffic_record = build_traffic_alert(
                            cand, observation, verdict, config, run_id, obs_path, formal_alert_path)
                        traffic_path = write_traffic_alert(traffic_record, config)
                        print(
                            "[traffic_alert] "
                            f"level={traffic_record.get('level', '')} "
                            f"pid={traffic_record.get('pid', 0)} "
                            f"process={traffic_record.get('process', '')} "
                            f"dst={traffic_record.get('dst_ip', '')}:{traffic_record.get('dst_port', 0)} "
                            f"json={traffic_path}"
                        )
                    except Exception as e:
                        errors.append(f"traffic_alert_error pid={cand.get('pid')}: {e}")

            except Exception as e:
                errors.append(f"observe_error pid={cand.get('pid')}: {e}")
    else:
        # Dry-run mode
        for cand in confirmed:
            try:
                plan = build_observation_plan(cand, config)
                from datetime import datetime, timezone
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "run_id": run_id,
                    "agent_mode": agent_cfg.get("mode", "manual"),
                    "dry_run": True,
                    "pid": cand["pid"],
                    "process_name": cand["name"],
                    "exe_hash": "",
                    "verdict": "candidate_observation_planned",
                    "reasons": cand["reasons"],
                    "hit_count": cand.get("hit_count", 0),
                    "observation_plan": plan,
                }
                path = write_alert(alert, config)
                alerts_path = path
                confirmed_alerts_written += 1
            except Exception as e:
                errors.append(f"alert_error pid={cand.get('pid')}: {e}")

    from .candidate_state import _state_path
    state_path = _state_path(config)

    return {
        "run_id": run_id,
        "mode": agent_cfg.get("mode", "manual"),
        "dry_run": dry_run,
        "process_count": len(processes),
        "raw_candidate_count": len(candidates),
        "confirmed_candidate_count": len(confirmed),
        "pending_candidate_count": len(pending),
        "suppressed_candidate_count": suppressed_count,
        "min_consecutive_hits": min_hits,
        "state_path": state_path,
        "top_candidates": [
            {"pid": c["pid"], "name": c["name"], "score": c["score"],
             "reasons": c["reasons"], "hit_count": c.get("hit_count", 0)}
            for c in confirmed[:max_cand]
        ],
        "pending_candidates": [
            {"pid": c["pid"], "name": c["name"], "score": c["score"],
             "reasons": c["reasons"], "hit_count": c.get("hit_count", 0)}
            for c in pending[:max_cand]
        ],
        "observed_count": observed_count,
        "observations_written": observations_written,
        "confirmed_alerts_written": confirmed_alerts_written,
        "suppressed_suspicious_alerts": suppressed_suspicious_alerts,
        "skipped_observation_count": skipped_observation_count,
        "observation_eligible_count": observation_eligible_count,
        "weak_candidate_count": weak_candidate_count,
        "last_alert_verdict": last_alert_verdict,
        "last_alert_pid": last_alert_pid,
        "last_alert_process": last_alert_process,
        "warning_log_path": warning_log_path,
        "confirmed_mining_count": confirmed_mining_count,
        "protocol_suspicious_count": protocol_suspicious_count,
        "fallback_suspicious_count": fallback_suspicious_count,
        "alerts_path": alerts_path,
        "scanner_warning": scanner_warning,
        "errors": errors,
    }


def run_loop(config: dict):
    """Run scan loop until interrupted."""
    agent_cfg = config.get("agent", {})
    interval = agent_cfg.get("scan_interval_sec", 10)
    dry_run = agent_cfg.get("dry_run", True)

    if not dry_run and os.geteuid() != 0:
        print("[agent] ERROR: non-dry-run mode requires root. Please run with sudo.")
        sys.exit(1)

    if dry_run and os.geteuid() != 0:
        print("[agent] WARNING: running without root, some process info may be limited")

    print_startup_banner(config)

    observation_state = {}
    random_enabled = random_observer_enabled(config) and not dry_run
    random_interval = random_observer_interval(config)
    random_cfg = config.get("random_observer", {})
    random_run_at_start = random_cfg.get("run_at_start", True)
    next_random_observation_at = time.time() if random_run_at_start else time.time() + random_interval

    try:
        while True:
            summary = run_once(config, observation_state)
            print_scan_summary(summary, config)
            if summary["errors"]:
                for err in summary["errors"]:
                    if not err.startswith("warning"):
                        print(f"[agent] ERROR: {err}")

            if random_enabled and time.time() >= next_random_observation_at:
                try:
                    random_summary = run_random_observation(config)
                    print(
                        f"[{format_display_time(config)}] [random_observation] "
                        f"pid={random_summary.get('pid', 0)} "
                        f"process={random_summary.get('process_name', '')} "
                        f"result={random_summary.get('result', '')} "
                        f"verdict={random_summary.get('verdict', '')} "
                        f"json={random_summary.get('path', '')}"
                    )
                except Exception as e:
                    print(f"[random_observation] ERROR: {e}")
                next_random_observation_at = time.time() + random_interval

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[agent] Stopped by user")
