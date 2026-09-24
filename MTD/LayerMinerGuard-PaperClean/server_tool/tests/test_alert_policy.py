"""Tests for alert policy — confirmed-only alerts, observations always written."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.manual_agent import run_once


def _live_config(emit_confirmed=True, emit_suspicious=False, emit_fallback=False):
    tmpdir = tempfile.mkdtemp()
    return {
        "agent": {
            "mode": "manual_live", "auto_start": False, "dry_run": False,
            "scan_interval_sec": 10, "observe_duration_sec": 5,
            "cooldown_sec": 600, "require_root_for_real_probe": True,
            "default_action": "alert_only", "max_runtime_observations_per_loop": 1,
        },
        "candidate": {
            "min_cpu_percent": 70, "min_runtime_sec": 30, "require_network": True,
            "max_candidates_per_scan": 10, "ignore_kernel_threads": True,
            "min_consecutive_hits": 1, "state_ttl_sec": 900,
            "ignore_system_services": True, "ignore_service_users": ["root"],
            "whitelist_names": [], "whitelist_paths": [],
        },
        "observer": {
            "probe_mode": "on_demand", "enable_plaintext_probe": True,
            "enable_tls_probe": True, "dry_run_only": False,
            "plaintext_probe_duration_sec": 5, "tls_probe_duration_sec": 5,
            "probe_timeout_sec": 10,
        },
        "verdict": {
            "require_compute_evidence": True, "compute_cpu_threshold_percent": 30,
            "confirmed_require_job": True, "confirmed_require_submit": True,
            "confirmed_require_association": True, "suspicious_allow_job_only": True,
        },
        "alert_policy": {
            "emit_confirmed_alerts": emit_confirmed,
            "emit_protocol_suspicious_alerts": emit_suspicious,
            "emit_fallback_suspicious_alerts": emit_fallback,
            "write_all_observations": True,
            "alert_severity_confirmed": "high",
            "alert_severity_suspicious": "medium",
        },
        "privacy": {
            "save_raw_payload": False, "save_wallet": False, "save_job_id": False,
            "save_nonce": False, "save_result": False, "save_blob": False,
            "save_full_cmdline": False, "save_remote_endpoint_raw": False,
        },
        "output": {
            "log_dir": tmpdir, "state_dir": tmpdir,
            "alerts_jsonl": os.path.join(tmpdir, "alerts.jsonl"),
            "candidate_state_json": os.path.join(tmpdir, "candidate_state.json"),
            "observation_dir": os.path.join(tmpdir, "observations"),
        },
    }


class TestAlertPolicy:
    def test_live_mode_rejected_without_root(self):
        if os.geteuid() == 0:
            return
        config = _live_config()
        summary = run_once(config)
        assert "non_dry_run_requires_root" in summary["errors"]

    def test_confirmed_alert_fields_in_summary(self):
        config = _live_config()
        summary = run_once(config)
        assert "confirmed_alerts_written" in summary
        assert "observations_written" in summary
        assert "suppressed_suspicious_alerts" in summary
