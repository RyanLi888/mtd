"""JSON alert schema for LayerMinerGuard server tool.

Builds confirmed alerts and observation records with fixed schema.
Never saves raw payload, wallet, job_id, nonce, result, blob, or full cmdline.
"""

import socket
from datetime import datetime, timezone


def build_confirmed_alert(candidate: dict, observation: dict, verdict: dict,
                          config: dict, run_id: str) -> dict:
    """Build a confirmed mining alert with fixed schema.

    Args:
        candidate: Confirmed candidate dict.
        observation: Observation summary from live_observer.
        verdict: Verdict dict from live_verdict.
        config: Configuration dict.
        run_id: Current run ID.

    Returns:
        Alert dict conforming to JSON alert schema v1.0.
    """
    proc = candidate.get("process", {})
    policy = config.get("alert_policy", {})
    severity = policy.get("alert_severity_confirmed", "high")

    plain = observation.get("plaintext", {})
    tls = observation.get("tls", {})

    return {
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "host": socket.gethostname(),
        "agent_mode": config.get("agent", {}).get("mode", "manual_live"),
        "alert_type": "confirmed_mining",
        "severity": severity,
        "verdict": verdict.get("verdict", ""),
        "confidence": verdict.get("confidence", ""),
        "pid": candidate.get("pid", 0),
        "process_name": candidate.get("name", ""),
        "process_user": proc.get("username", ""),
        "exe_path": proc.get("exe_path", ""),
        "exe_hash": proc.get("exe_hash", ""),
        "cmdline_hash": proc.get("cmdline_hash", ""),
        "visibility_mode": verdict.get("visibility_mode", ""),
        "visibility_boundary": verdict.get("visibility_boundary"),
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
        "recommended_action": "inspect_or_stop_process",
    }


def build_observation_record(candidate: dict, observation: dict, verdict: dict,
                             config: dict, run_id: str) -> dict:
    """Build an observation record (always written, regardless of alert policy).

    Args:
        candidate: Candidate dict.
        observation: Observation summary.
        verdict: Verdict dict.
        config: Configuration dict.
        run_id: Current run ID.

    Returns:
        Observation record dict.
    """
    proc = candidate.get("process", {})
    plain = observation.get("plaintext", {})
    tls = observation.get("tls", {})

    return {
        "schema_version": "1.0",
        "record_type": "observation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "host": socket.gethostname(),
        "agent_mode": config.get("agent", {}).get("mode", "manual_live"),
        "pid": candidate.get("pid", 0),
        "process_name": candidate.get("name", ""),
        "process_user": proc.get("username", ""),
        "exe_hash": proc.get("exe_hash", ""),
        "cmdline_hash": proc.get("cmdline_hash", ""),
        "verdict": verdict.get("verdict", ""),
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
