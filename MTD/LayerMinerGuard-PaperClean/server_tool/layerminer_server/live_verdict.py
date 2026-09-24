"""Live verdict decision for LayerMinerGuard server tool.

Decides mining verdict based on observation evidence.
"""


def decide_live_verdict(observation: dict, config: dict) -> dict:
    """Decide live mining verdict from observation evidence.

    Args:
        observation: Observation summary from live_observer.
        config: Configuration dict with verdict rules.

    Returns:
        Verdict dict with verdict, confidence, visibility_mode,
        visibility_boundary, reasons.
    """
    # Handle skipped observations (stale PID)
    if observation.get("observe_skipped", False):
        skip_reason = observation.get("skip_reason", "unknown")
        return {
            "verdict": "benign_or_unconfirmed",
            "confidence": "none",
            "visibility_mode": "none",
            "visibility_boundary": "observation_skipped",
            "reasons": [f"observation_skipped:{skip_reason}"],
        }

    verdict_cfg = config.get("verdict", {})
    require_compute = verdict_cfg.get("require_compute_evidence", True)
    require_job = verdict_cfg.get("confirmed_require_job", True)
    require_submit = verdict_cfg.get("confirmed_require_submit", True)
    require_assoc = verdict_cfg.get("confirmed_require_association", True)
    suspicious_job_only = verdict_cfg.get("suspicious_allow_job_only", True)

    compute_present = observation.get("compute_evidence_present", False)
    plain = observation.get("plaintext", {})
    tls = observation.get("tls", {})

    plain_enabled = plain.get("enabled", False)
    tls_enabled = tls.get("enabled", False)
    has_libssl = observation.get("has_libssl", False)

    plain_job = plain.get("job_marker_count", 0) > 0
    plain_submit = plain.get("submit_marker_count", 0) > 0
    plain_assoc = plain.get("associated_submit_count", 0) > 0

    tls_job = tls.get("job_marker_count", 0) > 0
    tls_submit = tls.get("submit_marker_count", 0) > 0
    tls_assoc = tls.get("associated_submit_count", 0) > 0

    # Aggregate markers
    has_job = plain_job or tls_job
    has_submit = plain_submit or tls_submit
    has_assoc = plain_assoc or tls_assoc

    reasons = []
    visibility = "none"
    visibility_boundary = None

    # Determine visibility
    if plain_job or plain_submit:
        visibility = "plaintext_stratum"
    if tls_job or tls_submit:
        visibility = "openssl_tls" if visibility == "none" else "plaintext_and_tls"

    # Determine visibility boundary when no markers found
    if visibility == "none":
        if not plain_enabled and not tls_enabled:
            visibility_boundary = "no_probe_enabled"
        elif plain_enabled and not tls_enabled and not has_libssl:
            visibility_boundary = "no_dynamic_libssl_mapping"
        elif plain_enabled and not tls_enabled and has_libssl:
            visibility_boundary = "tls_probe_disabled"
        elif plain_enabled and tls_enabled:
            visibility_boundary = "encrypted_or_no_markers"
        elif not plain_enabled and tls_enabled:
            visibility_boundary = "plaintext_disabled"

    # Build reasons
    if compute_present:
        reasons.append("compute_evidence_present")
    if has_job:
        reasons.append("job_marker_seen")
    if has_submit:
        reasons.append("submit_marker_seen")
    if has_assoc:
        reasons.append("association_seen")
    if observation.get("early_confirmed", False):
        reasons.append("early_confirmed")
    if visibility_boundary:
        reasons.append(f"visibility_boundary:{visibility_boundary}")

    # Decision logic
    # confirmed_mining_live: compute + job + submit + association
    if (not require_compute or compute_present) and \
       (not require_job or has_job) and \
       (not require_submit or has_submit) and \
       (not require_assoc or has_assoc):
        return {
            "verdict": "confirmed_mining_live",
            "confidence": "high",
            "visibility_mode": visibility,
            "visibility_boundary": visibility_boundary,
            "reasons": sorted(reasons),
        }

    # protocol_suspicious: compute + job (and maybe submit) but no full association
    if compute_present and has_job and suspicious_job_only:
        reasons_susp = [r for r in reasons if r != "association_seen"]
        return {
            "verdict": "protocol_suspicious",
            "confidence": "medium",
            "visibility_mode": visibility,
            "visibility_boundary": visibility_boundary,
            "reasons": sorted(reasons_susp),
        }

    # fallback_suspicious: compute + network but no protocol markers
    if compute_present:
        return {
            "verdict": "fallback_suspicious",
            "confidence": "low",
            "visibility_mode": visibility,
            "visibility_boundary": visibility_boundary,
            "reasons": sorted(reasons),
        }

    # benign_or_unconfirmed
    return {
        "verdict": "benign_or_unconfirmed",
        "confidence": "none",
        "visibility_mode": visibility,
        "visibility_boundary": visibility_boundary,
        "reasons": sorted(reasons),
    }
