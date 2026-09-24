"""Periodic random process observation for live monitoring.

This module does not change candidate selection or formal alert policy. It
samples one process at a configured interval, runs the existing short-window
observer, and writes a standalone JSON record with normal/abnormal result.
"""

import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

from . import result_mirror
from .live_observer import observe_candidate_live
from .live_verdict import decide_live_verdict
from .process_scanner import scan_processes
from .traffic_alert_store import (
    build_traffic_alert,
    has_abnormal_traffic_evidence,
    traffic_alerts_enabled,
    write_traffic_alert,
)


_ABNORMAL_VERDICTS = {
    "confirmed_mining_live",
    "protocol_suspicious",
    "fallback_suspicious",
}


def _random_cfg(config: dict) -> dict:
    return config.get("random_observer", {})


def random_observer_enabled(config: dict) -> bool:
    """Return whether periodic random observation is enabled."""
    return _random_cfg(config).get("enabled", False)


def random_observer_interval(config: dict) -> int:
    """Return periodic random observation interval in seconds."""
    return int(_random_cfg(config).get("interval_sec", 1800))


def _parse_record_timestamp(path: str) -> datetime:
    """Return a random observation timestamp from JSON or file mtime."""
    try:
        with open(path) as f:
            data = json.load(f)
        ts = data.get("timestamp", "")
        if ts:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    try:
        return datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
    except OSError:
        return datetime.now(timezone.utc)


def cleanup_random_observations(config: dict) -> dict:
    """Apply retention policy to random observation JSON files.

    Default policy: when the oldest record reaches 40 days old, delete all
    records older than 30 days. In the normal steady state, this clears the
    oldest 10 days and keeps about one month of records.
    """
    cfg = _random_cfg(config)
    trigger_days = int(cfg.get("retention_trigger_days", 40))
    keep_days = int(cfg.get("retention_keep_days", 30))
    directory = result_mirror.result_path(config, "random_observations")
    if not os.path.isdir(directory):
        return {"deleted": 0, "checked": 0, "reason": "directory_missing"}

    now = datetime.now(timezone.utc)
    records = []
    for fname in os.listdir(directory):
        if not fname.endswith(".json") or fname.startswith("."):
            continue
        path = os.path.join(directory, fname)
        ts = _parse_record_timestamp(path)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        records.append((path, ts))

    if not records:
        return {"deleted": 0, "checked": 0, "reason": "no_records"}

    oldest_ts = min(ts for _, ts in records)
    oldest_age_days = (now - oldest_ts).days
    if oldest_age_days < trigger_days:
        return {
            "deleted": 0,
            "checked": len(records),
            "reason": "below_trigger",
            "oldest_age_days": oldest_age_days,
        }

    cutoff = now - timedelta(days=keep_days)
    deleted = 0
    for path, ts in records:
        if ts < cutoff:
            try:
                os.remove(path)
                deleted += 1
            except OSError:
                pass

    return {
        "deleted": deleted,
        "checked": len(records),
        "reason": "retention_applied",
        "oldest_age_days": oldest_age_days,
        "cutoff": cutoff.isoformat(),
    }


def _eligible_random_processes(processes: list[dict], config: dict) -> list[dict]:
    cfg = _random_cfg(config)
    include_kernel = cfg.get("include_kernel_threads", False)
    include_self = cfg.get("include_self", False)
    excluded_names = set(cfg.get("exclude_names", []))
    current_pid = os.getpid()

    eligible = []
    for proc in processes:
        pid = proc.get("pid", 0)
        name = proc.get("name", "")
        if not include_self and pid == current_pid:
            continue
        if not include_kernel and proc.get("kernel_thread", False):
            continue
        if name in excluded_names:
            continue
        if pid <= 1:
            continue
        eligible.append(proc)
    return eligible


def _candidate_from_process(proc: dict) -> dict:
    return {
        "pid": proc.get("pid", 0),
        "name": proc.get("name", ""),
        "score": 0.0,
        "reasons": ["periodic_random_probe"],
        "process": proc,
        "observation_eligible": True,
        "observation_priority": 0,
        "observation_block_reason": "",
    }


def _result_from_verdict(verdict_name: str, observation: dict) -> str:
    if observation.get("observe_skipped", False):
        return "normal"
    if verdict_name in _ABNORMAL_VERDICTS:
        return "abnormal"
    return "normal"


def _record(candidate: dict, observation: dict, verdict: dict, config: dict) -> dict:
    proc = candidate.get("process", {})
    plain = observation.get("plaintext", {})
    tls = observation.get("tls", {})
    verdict_name = verdict.get("verdict", "")
    result = _result_from_verdict(verdict_name, observation)

    return {
        "schema_version": "1.0",
        "record_type": "periodic_random_observation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": result,
        "is_abnormal": result == "abnormal",
        "note": "Periodic random probe; does not change formal alert policy.",
        "pid": candidate.get("pid", 0),
        "process_name": candidate.get("name", ""),
        "process_user": proc.get("username", ""),
        "exe_path": proc.get("exe_path", ""),
        "exe_hash": proc.get("exe_hash", ""),
        "cmdline_hash": proc.get("cmdline_hash", ""),
        "verdict": verdict_name,
        "confidence": verdict.get("confidence", ""),
        "visibility_mode": verdict.get("visibility_mode", ""),
        "visibility_boundary": verdict.get("visibility_boundary"),
        "reasons": verdict.get("reasons", []),
        "evidence": {
            "compute_evidence_present": observation.get("compute_evidence_present", False),
            "cpu_avg_percent": observation.get("cpu_avg_percent", 0.0),
            "job_marker_count": plain.get("job_marker_count", 0) + tls.get("job_marker_count", 0),
            "submit_marker_count": plain.get("submit_marker_count", 0) + tls.get("submit_marker_count", 0),
            "associated_submit_count": plain.get("associated_submit_count", 0) + tls.get("associated_submit_count", 0),
            "plaintext_job_marker_count": plain.get("job_marker_count", 0),
            "plaintext_submit_marker_count": plain.get("submit_marker_count", 0),
            "plaintext_associated_submit_count": plain.get("associated_submit_count", 0),
            "tls_job_marker_count": tls.get("job_marker_count", 0),
            "tls_submit_marker_count": tls.get("submit_marker_count", 0),
            "tls_associated_submit_count": tls.get("associated_submit_count", 0),
        },
        "observation": {
            "observe_duration_sec": observation.get("observe_duration_sec", 0),
            "actual_observe_duration_sec": observation.get("actual_observe_duration_sec", 0),
            "early_confirmed": observation.get("early_confirmed", False),
            "probe_mode": config.get("observer", {}).get("probe_mode", "on_demand"),
            "plaintext_probe_enabled": plain.get("enabled", False),
            "tls_probe_enabled": tls.get("enabled", False),
            "observe_skipped": observation.get("observe_skipped", False),
            "skip_reason": observation.get("skip_reason", ""),
        },
        "privacy": {
            "raw_payload_saved": False,
            "wallet_saved": False,
            "job_id_saved": False,
            "nonce_saved": False,
            "result_saved": False,
            "blob_saved": False,
            "full_cmdline_saved": False,
        },
    }


def _write_record(record: dict, config: dict) -> str:
    ts = record.get("timestamp", "unknown").replace(":", "").replace("-", "")[:15]
    pid = record.get("pid", 0)
    result = record.get("result", "unknown")
    filename = f"{ts}_{pid}_{result}.json"
    out_dir = result_mirror.ensure_result_dir(config, "random_observations")
    path = os.path.join(out_dir, filename)
    with open(path, "w") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
    return path


def run_random_observation(config: dict) -> dict:
    """Run one random process observation and write its JSON record."""
    processes = scan_processes(config)
    eligible = _eligible_random_processes(processes, config)
    if not eligible:
        record = {
            "schema_version": "1.0",
            "record_type": "periodic_random_observation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": "normal",
            "is_abnormal": False,
            "verdict": "no_process_available",
            "note": "No eligible process was available for periodic random probe.",
        }
        path = _write_record(record, config)
        cleanup = cleanup_random_observations(config)
        return {
            "written": True,
            "path": path,
            "pid": 0,
            "result": "normal",
            "verdict": "no_process_available",
            "retention_deleted": cleanup.get("deleted", 0),
        }

    proc = random.choice(eligible)
    candidate = _candidate_from_process(proc)

    observer_override = dict(config.get("observer", {}))
    random_cfg = _random_cfg(config)
    duration = random_cfg.get("probe_duration_sec")
    if duration is not None:
        observer_override["plaintext_probe_duration_sec"] = int(duration)
        observer_override["tls_probe_duration_sec"] = int(duration)
        observer_override["probe_timeout_sec"] = int(random_cfg.get("probe_timeout_sec", int(duration) + 60))

    random_config = dict(config)
    random_config["observer"] = observer_override

    observation = observe_candidate_live(candidate, random_config)
    verdict = decide_live_verdict(observation, random_config)
    record = _record(candidate, observation, verdict, random_config)
    path = _write_record(record, config)
    traffic_alert_path = ""
    if traffic_alerts_enabled(config) and has_abnormal_traffic_evidence(observation, verdict):
        traffic_record = build_traffic_alert(
            candidate, observation, verdict, config, f"random-{uuid.uuid4().hex[:12]}", path, "")
        traffic_alert_path = write_traffic_alert(traffic_record, config)
    cleanup = cleanup_random_observations(config)

    return {
        "written": True,
        "path": path,
        "pid": candidate.get("pid", 0),
        "process_name": candidate.get("name", ""),
        "result": record.get("result", ""),
        "verdict": verdict.get("verdict", ""),
        "traffic_alert_path": traffic_alert_path,
        "retention_deleted": cleanup.get("deleted", 0),
    }
