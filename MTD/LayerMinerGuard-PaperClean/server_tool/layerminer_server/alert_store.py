"""Alert store for LayerMinerGuard server tool.

Writes sanitized alerts to JSONL. Never saves raw payload, wallet,
job_id, nonce, result, blob, or full cmdline.
"""

import json
import os
from datetime import datetime, timezone

from . import result_mirror


_FIELDS_TO_REMOVE = {
    "raw_payload", "payload", "wallet", "job_id",
    "nonce", "result", "blob", "full_cmdline",
    "pool_user", "pool_password",
}


def sanitize_alert(alert: dict) -> dict:
    """Remove or redact sensitive fields from an alert dict.

    Args:
        alert: Raw alert dict.

    Returns:
        Sanitized alert dict with sensitive fields removed.
    """
    sanitized = {}
    for k, v in alert.items():
        if k in _FIELDS_TO_REMOVE:
            continue
        if isinstance(v, dict):
            sanitized[k] = sanitize_alert(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_alert(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


def write_alert(alert: dict, config: dict) -> str:
    """Write a sanitized alert to JSONL file.

    Args:
        alert: Alert dict (will be sanitized before writing).
        config: Configuration dict with output settings.

    Returns:
        Path to the alerts file.
    """
    output_cfg = config.get("output", {})
    alerts_path = output_cfg.get("alerts_jsonl", "/var/log/layerminer/alerts.jsonl")

    # Fallback if no write permission
    fallback = "/tmp/layerminer/alerts.jsonl"
    use_fallback = False

    # Ensure parent directory exists
    parent = os.path.dirname(alerts_path)
    try:
        os.makedirs(parent, exist_ok=True)
    except PermissionError:
        os.makedirs(os.path.dirname(fallback), exist_ok=True)
        alerts_path = fallback
        use_fallback = True

    # Test write permission
    try:
        with open(alerts_path, 'a') as f:
            pass
    except PermissionError:
        os.makedirs(os.path.dirname(fallback), exist_ok=True)
        alerts_path = fallback
        use_fallback = True

    # Add timestamp if missing
    if "timestamp" not in alert:
        alert["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Ensure privacy block
    if "privacy" not in alert:
        alert["privacy"] = {
            "raw_payload_saved": False,
            "wallet_saved": False,
            "job_id_saved": False,
            "nonce_saved": False,
            "result_saved": False,
            "blob_saved": False,
        }

    sanitized = sanitize_alert(alert)

    with open(alerts_path, 'a') as f:
        f.write(json.dumps(sanitized, ensure_ascii=False) + "\n")

    result_mirror.append_jsonl(config, "alerts.jsonl", sanitized)

    return alerts_path


def read_recent_alerts(config: dict, limit: int = 20) -> list[dict]:
    """Read recent alerts from JSONL file.

    Args:
        config: Configuration dict with output settings.
        limit: Maximum number of alerts to return.

    Returns:
        List of alert dicts (most recent last).
    """
    output_cfg = config.get("output", {})
    alerts_path = output_cfg.get("alerts_jsonl", "/var/log/layerminer/alerts.jsonl")
    fallback = "/tmp/layerminer/alerts.jsonl"

    path = alerts_path if os.path.exists(alerts_path) else fallback
    if not os.path.exists(path):
        return []

    alerts = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except PermissionError:
        return []

    return alerts[-limit:]


def write_observation_record(record: dict, config: dict) -> str:
    """Write a sanitized observation record to individual JSON file.

    Args:
        record: Observation record dict (will be sanitized).
        config: Configuration dict with output settings.

    Returns:
        Path to the written observation file.
    """
    output_cfg = config.get("output", {})
    obs_dir = output_cfg.get("observation_dir", "/var/log/layerminer/observations")
    fallback_dir = "/tmp/layerminer/observations"

    # Try primary dir
    try:
        os.makedirs(obs_dir, exist_ok=True)
    except PermissionError:
        obs_dir = fallback_dir
        os.makedirs(obs_dir, exist_ok=True)

    # Test write permission
    try:
        test_path = os.path.join(obs_dir, ".test")
        with open(test_path, 'w') as f:
            pass
        os.remove(test_path)
    except PermissionError:
        obs_dir = fallback_dir
        os.makedirs(obs_dir, exist_ok=True)

    sanitized = sanitize_alert(record)

    # Filename: <timestamp>_<pid>_<verdict>.json
    ts = sanitized.get("timestamp", "unknown").replace(":", "").replace("-", "")[:15]
    pid = sanitized.get("pid", 0)
    verdict_name = sanitized.get("verdict", "unknown").replace("_", "-")
    filename = f"{ts}_{pid}_{verdict_name}.json"

    path = os.path.join(obs_dir, filename)
    with open(path, 'w') as f:
        json.dump(sanitized, f, indent=2, ensure_ascii=False)

    result_mirror.write_observation(config, filename, sanitized)

    return path


def read_recent_observations(config: dict, limit: int = 10) -> list[dict]:
    """Read recent observation records from observation directory.

    Args:
        config: Configuration dict with output settings.
        limit: Maximum number of records to return.

    Returns:
        List of observation record dicts (most recent last).
    """
    output_cfg = config.get("output", {})
    obs_dir = output_cfg.get("observation_dir", "/var/log/layerminer/observations")
    fallback_dir = "/tmp/layerminer/observations"

    directory = obs_dir if os.path.isdir(obs_dir) else fallback_dir
    if not os.path.isdir(directory):
        return []

    records = []
    try:
        files = sorted(os.listdir(directory))
        for fname in files[-limit:]:
            if fname.endswith(".json") and not fname.startswith("."):
                fpath = os.path.join(directory, fname)
                try:
                    with open(fpath) as f:
                        records.append(json.load(f))
                except (json.JSONDecodeError, OSError):
                    continue
    except PermissionError:
        return []

    return records
