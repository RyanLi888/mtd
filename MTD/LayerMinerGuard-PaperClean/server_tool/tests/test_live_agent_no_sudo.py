"""Tests for live agent — non-root rejection and alert sanitization."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.manual_agent import run_once
from server_tool.layerminer_server.alert_store import sanitize_alert


def _live_config():
    tmpdir = tempfile.mkdtemp()
    return {
        "agent": {
            "mode": "manual_live",
            "auto_start": False,
            "dry_run": False,  # Live mode
            "scan_interval_sec": 10,
            "observe_duration_sec": 90,
            "cooldown_sec": 600,
            "require_root_for_real_probe": True,
            "default_action": "alert_only",
            "max_runtime_observations_per_loop": 1,
        },
        "candidate": {
            "min_cpu_percent": 70, "min_runtime_sec": 30,
            "require_network": True, "max_candidates_per_scan": 10,
            "ignore_kernel_threads": True, "min_consecutive_hits": 2,
            "state_ttl_sec": 900, "ignore_system_services": True,
            "ignore_service_users": ["root"],
            "whitelist_names": [], "whitelist_paths": [],
        },
        "observer": {"enable_plaintext_probe": True, "enable_tls_probe": True, "dry_run_only": False},
        "verdict": {"require_compute_evidence": True, "compute_cpu_threshold_percent": 30},
        "privacy": {"save_raw_payload": False, "save_wallet": False, "save_job_id": False,
                    "save_nonce": False, "save_result": False, "save_blob": False, "save_full_cmdline": False},
        "output": {
            "log_dir": tmpdir, "state_dir": tmpdir,
            "alerts_jsonl": os.path.join(tmpdir, "alerts.jsonl"),
            "candidate_state_json": os.path.join(tmpdir, "candidate_state.json"),
        },
    }


class TestLiveModeRejection:
    def test_dry_run_false_rejected_without_root(self):
        """Live mode (dry_run=false) should reject when not root."""
        if os.geteuid() == 0:
            return  # Skip if running as root
        config = _live_config()
        summary = run_once(config)
        assert "non_dry_run_requires_root" in summary["errors"]
        assert summary["process_count"] == 0


class TestAlertSanitization:
    def test_removes_raw_payload(self):
        alert = {"pid": 1, "raw_payload": "sensitive", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "raw_payload" not in result

    def test_removes_wallet(self):
        alert = {"pid": 1, "wallet": "42sx...long", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "wallet" not in result

    def test_removes_job_id(self):
        alert = {"pid": 1, "job_id": "abc123", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "job_id" not in result

    def test_removes_nonce(self):
        alert = {"pid": 1, "nonce": "deadbeef", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "nonce" not in result

    def test_removes_blob(self):
        alert = {"pid": 1, "blob": "0100...", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "blob" not in result

    def test_removes_full_cmdline(self):
        alert = {"pid": 1, "full_cmdline": "/usr/bin/xmrig --user WALLET", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "full_cmdline" not in result

    def test_preserves_verdict(self):
        alert = {"pid": 1, "verdict": "confirmed_mining_live", "confidence": "high"}
        result = sanitize_alert(alert)
        assert result["verdict"] == "confirmed_mining_live"
        assert result["confidence"] == "high"


class TestCooldown:
    def test_cooldown_prevents_repeat_observation(self):
        from server_tool.layerminer_server.observer_scheduler import should_observe_now, record_observation
        config = {"agent": {"cooldown_sec": 600}}
        cand = {"pid": 1000, "name": "test", "process": {"exe_hash": "sha256:abc"}}
        state = {}

        # First time: should observe
        assert should_observe_now(cand, config, state) is True

        # Record observation
        record_observation(cand, {"verdict": "confirmed_mining_live"}, state)

        # Second time: should NOT observe (in cooldown)
        assert should_observe_now(cand, config, state) is False


class TestLiveYamlConfig:
    def test_auto_start_false(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml"
        )
        if os.path.exists(config_path):
            import yaml
            with open(config_path) as f:
                config = yaml.safe_load(f)
            assert config["agent"]["auto_start"] is False

    def test_dry_run_false(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml"
        )
        if os.path.exists(config_path):
            import yaml
            with open(config_path) as f:
                config = yaml.safe_load(f)
            assert config["agent"]["dry_run"] is False


class TestInstallScript:
    def test_no_systemctl_enable(self):
        install_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "packaging", "install.sh"
        )
        if os.path.exists(install_path):
            with open(install_path) as f:
                content = f.read()
            # Allow in echo/comment but not as actual command
            lines = content.split('\n')
            for line in lines:
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('echo'):
                    continue
                assert 'systemctl enable' not in stripped
                assert 'systemctl start' not in stripped
