"""Tests for json_schema module."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.json_schema import build_confirmed_alert, build_observation_record


def _candidate():
    return {
        "pid": 1234, "name": "xmigr", "score": 0.9,
        "reasons": ["high_cpu", "network_activity"],
        "process": {
            "pid": 1234, "name": "xmigr", "exe_path": "/tmp/xmigr",
            "exe_hash": "sha256:abc123", "username": "nobody",
            "cmdline_hash": "sha256:def456",
        },
    }


def _observation():
    return {
        "compute_evidence_present": True,
        "cpu_avg_percent": 85.0,
        "observe_duration_sec": 300,
        "plaintext": {
            "enabled": True, "job_marker_count": 10,
            "submit_marker_count": 2, "associated_submit_count": 1,
        },
        "tls": {
            "enabled": False, "job_marker_count": 0,
            "submit_marker_count": 0, "associated_submit_count": 0,
        },
    }


def _verdict():
    return {
        "verdict": "confirmed_mining_live",
        "confidence": "high",
        "visibility_mode": "plaintext_stratum",
        "reasons": ["compute_evidence_present", "job_marker_seen", "submit_marker_seen", "association_seen"],
    }


def _config():
    return {
        "agent": {"mode": "manual_live"},
        "observer": {"probe_mode": "on_demand"},
        "alert_policy": {"alert_severity_confirmed": "high"},
    }


class TestBuildConfirmedAlert:
    def test_schema_version(self):
        alert = build_confirmed_alert(_candidate(), _observation(), _verdict(), _config(), "abc123")
        assert alert["schema_version"] == "1.0"

    def test_alert_type(self):
        alert = build_confirmed_alert(_candidate(), _observation(), _verdict(), _config(), "abc123")
        assert alert["alert_type"] == "confirmed_mining"

    def test_has_required_fields(self):
        alert = build_confirmed_alert(_candidate(), _observation(), _verdict(), _config(), "abc123")
        required = [
            "schema_version", "timestamp", "run_id", "host", "agent_mode",
            "alert_type", "severity", "verdict", "confidence",
            "pid", "process_name", "exe_hash", "cmdline_hash",
            "visibility_mode", "evidence", "observation", "privacy",
            "recommended_action",
        ]
        for field in required:
            assert field in alert, f"Missing field: {field}"

    def test_evidence_counts(self):
        alert = build_confirmed_alert(_candidate(), _observation(), _verdict(), _config(), "abc123")
        ev = alert["evidence"]
        assert ev["plaintext_job_marker_count"] == 10
        assert ev["plaintext_submit_marker_count"] == 2
        assert ev["job_marker_count"] == 10

    def test_privacy_all_false(self):
        alert = build_confirmed_alert(_candidate(), _observation(), _verdict(), _config(), "abc123")
        for v in alert["privacy"].values():
            assert v is False

    def test_no_raw_payload(self):
        alert = build_confirmed_alert(_candidate(), _observation(), _verdict(), _config(), "abc123")
        alert_str = str(alert)
        assert "raw_payload" not in alert_str.lower() or "raw_payload_saved" in alert_str

    def test_no_wallet(self):
        alert = build_confirmed_alert(_candidate(), _observation(), _verdict(), _config(), "abc123")
        assert "wallet" not in alert or alert.get("wallet") is None

    def test_recommended_action(self):
        alert = build_confirmed_alert(_candidate(), _observation(), _verdict(), _config(), "abc123")
        assert alert["recommended_action"] == "inspect_or_stop_process"


class TestBuildObservationRecord:
    def test_record_type(self):
        rec = build_observation_record(_candidate(), _observation(), _verdict(), _config(), "abc123")
        assert rec["record_type"] == "observation"

    def test_has_reasons(self):
        rec = build_observation_record(_candidate(), _observation(), _verdict(), _config(), "abc123")
        assert "compute_evidence_present" in rec["reasons"]
