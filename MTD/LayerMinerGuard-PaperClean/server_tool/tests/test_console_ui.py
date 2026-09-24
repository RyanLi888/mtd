"""Tests for console_ui module."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.console_ui import (
    print_startup_banner,
    print_scan_summary,
    print_confirmed_warning,
    print_observation_notice,
)


def _config():
    return {
        "agent": {"mode": "manual_live", "scan_interval_sec": 10, "observe_duration_sec": 300,
                  "default_action": "alert_only", "auto_start": False},
        "observer": {"probe_mode": "on_demand"},
        "output": {"alerts_jsonl": "/var/log/layerminer/alerts.jsonl",
                   "observation_dir": "/var/lib/layerminer/observations"},
        "alert_policy": {"emit_confirmed_alerts": True, "emit_protocol_suspicious_alerts": False},
        "privacy": {"save_raw_payload": False, "save_wallet": False},
    }


def _summary():
    return {
        "run_id": "abc12345def6", "raw_candidate_count": 3, "confirmed_candidate_count": 1,
        "pending_candidate_count": 2, "observed_count": 1, "observations_written": 1,
        "confirmed_alerts_written": 1, "confirmed_mining_count": 1,
        "protocol_suspicious_count": 0, "fallback_suspicious_count": 0,
    }


def _alert():
    return {
        "verdict": "confirmed_mining_live", "severity": "high", "pid": 12345,
        "process_name": "xmrig", "process_user": "axkk",
        "visibility_mode": "plaintext_stratum", "visibility_boundary": None,
        "evidence": {"cpu_avg_percent": 96.4, "job_marker_count": 17,
                     "submit_marker_count": 2, "associated_submit_count": 1},
        "recommended_action": "inspect_or_stop_process",
    }


def _observation():
    return {
        "pid": 12345, "process_name": "xmrig", "verdict": "protocol_suspicious",
        "confidence": "medium", "visibility_mode": "plaintext_stratum",
        "visibility_boundary": None,
        "evidence": {"job_marker_count": 17, "submit_marker_count": 0, "associated_submit_count": 0},
    }


class TestStartupBanner:
    def test_no_sensitive_data(self, capsys):
        print_startup_banner(_config())
        out = capsys.readouterr().out
        assert "raw_payload" not in out
        assert "wallet" not in out or "wallet" in out.lower() and "not saved" in out.lower()
        assert "job_id" not in out or "not saved" in out

    def test_contains_mode(self, capsys):
        print_startup_banner(_config())
        out = capsys.readouterr().out
        assert "manual_live" in out

    def test_contains_probe_mode(self, capsys):
        print_startup_banner(_config())
        out = capsys.readouterr().out
        assert "on_demand" in out

    def test_contains_paths(self, capsys):
        print_startup_banner(_config())
        out = capsys.readouterr().out
        assert "/var/log/layerminer/alerts.jsonl" in out


class TestScanSummary:
    def test_contains_key_fields(self, capsys):
        print_scan_summary(_summary())
        out = capsys.readouterr().out
        assert "raw=3" in out
        assert "confirmed=1" in out
        assert "observed=1" in out
        assert "alerts=1" in out

    def test_no_sensitive_data(self, capsys):
        print_scan_summary(_summary())
        out = capsys.readouterr().out
        assert "raw_payload" not in out
        assert "wallet" not in out


class TestConfirmedWarning:
    def test_prints_key_fields(self, capsys):
        print_confirmed_warning(_alert(), "/var/log/layerminer/alerts.jsonl")
        out = capsys.readouterr().out
        assert "MINING WARNING" in out
        assert "confirmed_mining_live" in out
        assert "12345" in out
        assert "xmrig" in out
        assert "job=17" in out
        assert "submit=2" in out
        assert "assoc=1" in out

    def test_no_raw_payload(self, capsys):
        print_confirmed_warning(_alert())
        out = capsys.readouterr().out
        assert "raw_payload" not in out
        assert "wallet" not in out


class TestObservationNotice:
    def test_contains_verdict(self, capsys):
        print_observation_notice(_observation(), "/tmp/obs.json")
        out = capsys.readouterr().out
        assert "protocol_suspicious" in out
        assert "12345" in out
        assert "xmrig" in out

    def test_contains_record_path(self, capsys):
        print_observation_notice(_observation(), "/tmp/obs.json")
        out = capsys.readouterr().out
        assert "/tmp/obs.json" in out

    def test_handles_missing_fields(self, capsys):
        print_observation_notice({}, "")
        out = capsys.readouterr().out
        assert "observation" in out


class TestMissingFields:
    def test_banner_no_crash(self, capsys):
        print_startup_banner({})
        out = capsys.readouterr().out
        assert "LayerMinerGuard" in out

    def test_summary_no_crash(self, capsys):
        print_scan_summary({})
        out = capsys.readouterr().out
        assert "raw=" in out

    def test_warning_no_crash(self, capsys):
        print_confirmed_warning({}, "")
        out = capsys.readouterr().out
        assert "MINING WARNING" in out
