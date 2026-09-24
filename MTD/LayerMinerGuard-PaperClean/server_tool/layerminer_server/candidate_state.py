"""Candidate state management for sustained confirmation.

Tracks candidate appearances across scans. Only candidates that appear
in min_consecutive_hits consecutive scans are promoted to confirmed.
Uses identity_key (pid:create_time:exe_hash) to prevent stale PID reuse.
"""

import json
import os
import time
from datetime import datetime, timezone

from . import result_mirror


def _epoch_to_iso(ts: float) -> str:
    """Convert epoch seconds to readable UTC ISO string."""
    try:
        if not ts:
            return ""
        return datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
    except (OSError, ValueError, OverflowError, TypeError):
        return ""



def candidate_identity_key(candidate: dict) -> str:
    """Get the identity key for a candidate.

    Args:
        candidate: Candidate dict from candidate_selector.

    Returns:
        Identity key string.
    """
    proc = candidate.get("process", {})
    if "identity_key" in proc and proc["identity_key"]:
        return proc["identity_key"]
    # Fallback: build from components
    pid = candidate.get("pid", 0)
    create_time = proc.get("create_time", 0.0)
    exe_hash = proc.get("exe_hash", "")
    name = candidate.get("name", "")
    from .process_scanner import build_process_identity_key
    return build_process_identity_key(pid, create_time, exe_hash, name)


def _state_path(config: dict) -> str:
    """Get candidate state file path with fallback."""
    output_cfg = config.get("output", {})
    primary = output_cfg.get("candidate_state_json", "/var/lib/layerminer/candidate_state.json")
    fallback = "/tmp/layerminer/candidate_state.json"

    parent = os.path.dirname(primary)
    try:
        os.makedirs(parent, exist_ok=True)
        with open(primary, 'a') as f:
            pass
        return primary
    except PermissionError:
        os.makedirs(os.path.dirname(fallback), exist_ok=True)
        return fallback


def load_candidate_state(config: dict) -> dict:
    """Load candidate state from JSON file."""
    path = _state_path(config)
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, PermissionError):
        return {}


def save_candidate_state(state: dict, config: dict) -> str:
    """Save candidate state to JSON file."""
    path = _state_path(config)
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(state, f, indent=2)
    result_mirror.write_json(config, "candidate_state.json", state)
    return path


def update_candidate_state(candidates: list[dict], config: dict) -> tuple[list[dict], list[dict], dict]:
    """Update candidate state and return confirmed/pending lists.

    Stale entries (not in current candidates) are removed.

    Args:
        candidates: List of candidate dicts from candidate_selector.
        config: Configuration dict.

    Returns:
        Tuple of (confirmed_candidates, pending_candidates, state).
    """
    cand_cfg = config.get("candidate", {})
    min_hits = cand_cfg.get("min_consecutive_hits", 3)
    ttl_sec = cand_cfg.get("state_ttl_sec", 900)

    now = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()

    # Load existing state
    state = load_candidate_state(config)

    # Clean expired entries
    expired_keys = [
        k for k, v in state.items()
        if now - v.get("last_seen_ts", 0) > ttl_sec
    ]
    for k in expired_keys:
        del state[k]

    # Build set of current candidate identity keys
    active_keys = set()
    cand_by_key = {}
    for cand in candidates:
        key = candidate_identity_key(cand)
        active_keys.add(key)
        cand_by_key[key] = cand

    # Remove stale entries not in current candidates
    stale_keys = [k for k in state if k not in active_keys]
    for k in stale_keys:
        del state[k]

    # Update state for current candidates
    for cand in candidates:
        key = candidate_identity_key(cand)
        proc = cand.get("process", {})

        if key in state:
            # Existing candidate: increment hit_count
            state[key]["hit_count"] += 1
            create_time = proc.get("create_time", state[key].get("create_time", 0.0))
            state[key]["create_time_iso"] = _epoch_to_iso(create_time)
            state[key]["last_seen"] = now_iso
            state[key]["last_seen_ts"] = now
            state[key]["last_reasons"] = cand["reasons"]
        else:
            # New candidate
            create_time = proc.get("create_time", 0.0)
            state[key] = {
                "pid": cand.get("pid", 0),
                "name": cand["name"],
                "create_time": create_time,
                "create_time_iso": _epoch_to_iso(create_time),
                "exe_hash": proc.get("exe_hash", ""),
                "hit_count": 1,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "last_seen_ts": now,
                "last_reasons": cand["reasons"],
            }

    # Save state
    save_candidate_state(state, config)

    # Split into confirmed and pending (only from current candidates)
    # confirmed requires hit_count >= min_hits AND observation_eligible=true
    confirmed = []
    pending = []
    for cand in candidates:
        key = candidate_identity_key(cand)
        hit_count = state.get(key, {}).get("hit_count", 0)
        eligible = cand.get("observation_eligible", False)

        entry = {
            "pid": cand["pid"],
            "name": cand["name"],
            "score": cand["score"],
            "reasons": cand["reasons"],
            "hit_count": hit_count,
            "observation_eligible": eligible,
            "observation_priority": cand.get("observation_priority", 0),
            "observation_block_reason": cand.get("observation_block_reason", ""),
            "process": cand.get("process", {}),
        }

        if hit_count >= min_hits and eligible:
            confirmed.append(entry)
        else:
            pending.append(entry)

    return confirmed, pending, state
