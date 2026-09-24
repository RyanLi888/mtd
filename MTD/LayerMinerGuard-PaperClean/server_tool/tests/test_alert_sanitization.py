"""Tests for alert_store module — sanitization focus."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.alert_store import (
    sanitize_alert,
    write_alert,
    read_recent_alerts,
)


class TestSanitizeAlert:
    def test_removes_raw_payload(self):
        alert = {"pid": 1, "raw_payload": "sensitive data", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "raw_payload" not in result
        assert result["verdict"] == "test"

    def test_removes_wallet(self):
        alert = {"pid": 1, "wallet": "42sx...long_address", "verdict": "test"}
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

    def test_removes_result(self):
        alert = {"pid": 1, "result": "hash_result", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "result" not in result

    def test_removes_blob(self):
        alert = {"pid": 1, "blob": "0100...", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "blob" not in result

    def test_removes_full_cmdline(self):
        alert = {"pid": 1, "full_cmdline": "/usr/bin/xmrig --user WALLET", "verdict": "test"}
        result = sanitize_alert(alert)
        assert "full_cmdline" not in result

    def test_preserves_safe_fields(self):
        alert = {
            "pid": 1, "process_name": "xmrig", "verdict": "test",
            "reasons": ["high_cpu"], "dry_run": True,
        }
        result = sanitize_alert(alert)
        assert result["pid"] == 1
        assert result["process_name"] == "xmrig"
        assert result["verdict"] == "test"

    def test_nested_sanitization(self):
        alert = {
            "pid": 1,
            "observation_plan": {
                "raw_payload": "sensitive",
                "would_observe_tls": True,
            },
        }
        result = sanitize_alert(alert)
        assert "raw_payload" not in result["observation_plan"]
        assert result["observation_plan"]["would_observe_tls"] is True


class TestWriteAndReadAlerts:
    def test_write_and_read(self):
        config = {
            "output": {
                "alerts_jsonl": "/tmp/layerminer_test_alerts.jsonl",
            }
        }
        # Clean up
        path = config["output"]["alerts_jsonl"]
        if os.path.exists(path):
            os.remove(path)

        alert = {"pid": 1234, "process_name": "test", "verdict": "test"}
        written_path = write_alert(alert, config)
        assert written_path == path

        alerts = read_recent_alerts(config, limit=10)
        assert len(alerts) == 1
        assert alerts[0]["pid"] == 1234

        # Clean up
        os.remove(path)

    def test_fallback_on_permission_error(self):
        config = {
            "output": {
                "alerts_jsonl": "/root/no_permission/alerts.jsonl",
            }
        }
        alert = {"pid": 1234, "process_name": "test", "verdict": "test"}
        written_path = write_alert(alert, config)
        assert "/tmp/layerminer" in written_path

        # Clean up
        if os.path.exists(written_path):
            os.remove(written_path)
