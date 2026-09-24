"""Tests for manual_agent module — dry-run focus."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.manual_agent import load_config, run_once


def _test_config():
    """Create a test config with temporary paths."""
    tmpdir = tempfile.mkdtemp()
    return {
        "agent": {
            "mode": "manual",
            "auto_start": False,
            "dry_run": True,
            "scan_interval_sec": 10,
            "observe_duration_sec": 120,
            "cooldown_sec": 600,
            "require_root_for_real_probe": True,
            "default_action": "alert_only",
        },
        "candidate": {
            "min_cpu_percent": 80,
            "min_runtime_sec": 60,
            "require_network": True,
            "max_candidates_per_scan": 10,
            "ignore_kernel_threads": True,
            "ignore_system_services": True,
            "ignore_service_users": ["root", "avahi"],
            "min_consecutive_hits": 3,
            "state_ttl_sec": 900,
            "whitelist_names": ["systemd", "sshd"],
            "whitelist_paths": ["/usr/lib/systemd/", "/usr/sbin/"],
        },
        "observer": {
            "enable_plaintext_probe": True,
            "enable_tls_probe": True,
            "enable_cpu_telemetry": True,
            "max_concurrent_observations": 1,
            "max_prefix_bytes": 384,
            "dry_run_only": True,
        },
        "privacy": {
            "save_raw_payload": False,
            "save_wallet": False,
            "save_job_id": False,
            "save_nonce": False,
            "save_result": False,
            "save_blob": False,
            "save_full_cmdline": False,
        },
        "output": {
            "log_dir": tmpdir,
            "state_dir": tmpdir,
            "alerts_jsonl": os.path.join(tmpdir, "alerts.jsonl"),
            "candidate_state_json": os.path.join(tmpdir, "candidate_state.json"),
        },
    }


class TestRunOnce:
    def test_returns_summary_dict(self):
        config = _test_config()
        summary = run_once(config)
        assert isinstance(summary, dict)

    def test_summary_has_required_fields(self):
        config = _test_config()
        summary = run_once(config)
        required = [
            "run_id", "mode", "dry_run", "process_count",
            "raw_candidate_count", "confirmed_candidate_count",
            "pending_candidate_count", "suppressed_candidate_count",
            "min_consecutive_hits", "state_path",
            "top_candidates", "pending_candidates",
            "confirmed_alerts_written", "observations_written",
            "alerts_path", "scanner_warning", "errors",
        ]
        for field in required:
            assert field in summary, f"Missing field: {field}"

    def test_dry_run_flag_preserved(self):
        config = _test_config()
        summary = run_once(config)
        assert summary["dry_run"] is True

    def test_run_id_is_string(self):
        config = _test_config()
        summary = run_once(config)
        assert isinstance(summary["run_id"], str)
        assert len(summary["run_id"]) == 12

    def test_first_run_no_alerts(self):
        """First run should have 0 alerts since min_consecutive_hits=3."""
        config = _test_config()
        summary = run_once(config)
        assert summary["confirmed_alerts_written"] == 0

    def test_top_candidates_no_sensitive_data(self):
        config = _test_config()
        summary = run_once(config)
        for cand in summary["top_candidates"]:
            assert "cmdline" not in str(cand)
            assert "wallet" not in str(cand)
            assert "raw_payload" not in str(cand)


class TestLoadConfig:
    def test_loads_yaml(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "server.yaml"
        )
        if os.path.exists(config_path):
            config = load_config(config_path)
            assert "agent" in config
            assert config["agent"]["dry_run"] is True
