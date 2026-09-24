"""Observer scheduler for LayerMinerGuard server tool.

In dry-run mode, builds observation plans without launching real probes.
In live mode, manages cooldown to prevent repeated observations.
Uses identity_key (pid:create_time:exe_hash) for cooldown tracking.
"""

import time
from datetime import datetime, timezone
from .candidate_state import candidate_identity_key


def build_observation_plan(candidate: dict, config: dict) -> dict:
    """Build a dry-run observation plan for a candidate."""
    obs_cfg = config.get("observer", {})
    dry_run = obs_cfg.get("dry_run_only", True)
    proc = candidate.get("process", {})

    has_libssl = proc.get("has_libssl", False)
    has_network = proc.get("remote_count", 0) > 0
    reasons = list(candidate.get("reasons", []))

    would_observe_tls = has_libssl and obs_cfg.get("enable_tls_probe", True)
    would_observe_plain = has_network and obs_cfg.get("enable_plaintext_probe", True)
    would_collect_cpu = obs_cfg.get("enable_cpu_telemetry", True)

    if would_observe_tls:
        reasons.append("would_observe_tls")
    if would_observe_plain:
        reasons.append("would_observe_plaintext")

    if has_libssl and has_network:
        visibility_hint = "openssl_visible_tls_or_plaintext"
    elif has_libssl:
        visibility_hint = "openssl_visible_tls"
    elif has_network:
        visibility_hint = "plaintext_only"
    else:
        visibility_hint = "no_visibility"

    return {
        "pid": candidate.get("pid"),
        "dry_run": dry_run,
        "would_collect_cpu": would_collect_cpu,
        "would_observe_plaintext": would_observe_plain,
        "would_observe_tls": would_observe_tls,
        "would_run_plaintext_probe": False if dry_run else would_observe_plain,
        "would_run_tls_probe": False if dry_run else would_observe_tls,
        "visibility_hint": visibility_hint,
        "reason": sorted(set(reasons)),
    }


def should_observe_now(candidate: dict, config: dict, observation_state: dict) -> bool:
    """Check if a candidate should be observed now (cooldown check).

    Uses identity_key for tracking, not just pid:exe_hash.
    """
    agent_cfg = config.get("agent", {})
    cooldown_sec = agent_cfg.get("cooldown_sec", 600)

    key = candidate_identity_key(candidate)

    if key not in observation_state:
        return True

    last_obs = observation_state[key].get("last_observed_ts", 0)
    return (time.time() - last_obs) >= cooldown_sec


def record_observation(candidate: dict, verdict: dict, observation_state: dict):
    """Record that an observation was performed on a candidate."""
    key = candidate_identity_key(candidate)

    observation_state[key] = {
        "pid": candidate.get("pid", 0),
        "name": candidate.get("name", ""),
        "identity_key": key,
        "last_observed": datetime.now(timezone.utc).isoformat(),
        "last_observed_ts": time.time(),
        "last_verdict": verdict.get("verdict", ""),
    }
