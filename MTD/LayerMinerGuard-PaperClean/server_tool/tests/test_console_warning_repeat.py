"""Tests for console warning repeat and bell."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.console_ui import (
    print_confirmed_warning,
    format_warning_line,
    append_warning_log,
    print_scan_summary,
)
import tempfile


def _alert():
    return {
        "timestamp": "2026-06-25T15:29:25Z",
        "verdict": "confirmed_mining_live", "severity": "high", "pid": 38341,
        "process_name": "xmigr", "process_user": "axkk",
        "visibility_mode": "plaintext_stratum", "visibility_boundary": None,
        "evidence": {"cpu_avg_percent": 100.0, "job_marker_count": 16,
                     "submit_marker_count": 1, "associated_submit_count": 1},
        "recommended_action": "inspect_or_stop_process",
    }


def _config(repeat=3, bell=True, warn_log="/tmp/test_warnings.log"):
    return {
        "console": {
            "alert_repeat_count": repeat,
            "alert_repeat_interval_sec": 0,  # no delay in tests
            "terminal_bell": bell,
            "warning_log": warn_log,
        },
        "output": {"alerts_jsonl": "/tmp/alerts.jsonl"},
    }


class TestPrintConfirmedWarning:
    def test_repeat_count(self, capsys):
        print_confirmed_warning(_alert(), "/tmp/alerts.jsonl", _config(repeat=3))
        out = capsys.readouterr().out
        assert out.count("MINING WARNING") == 3
        assert "1/3" in out
        assert "2/3" in out
        assert "3/3" in out

    def test_terminal_bell(self, capsys):
        print_confirmed_warning(_alert(), "/tmp/alerts.jsonl", _config(bell=True))
        out = capsys.readouterr().out
        assert "\a" in out

    def test_no_bell_when_disabled(self, capsys):
        print_confirmed_warning(_alert(), "/tmp/alerts.jsonl", _config(bell=False))
        out = capsys.readouterr().out
        assert "\a" not in out

    def test_contains_key_fields(self, capsys):
        print_confirmed_warning(_alert(), "/tmp/alerts.jsonl", _config(repeat=1))
        out = capsys.readouterr().out
        assert "confirmed_mining_live" in out
        assert "38341" in out
        assert "xmigr" in out
        assert "job=16" in out
        assert "submit=1" in out
        assert "assoc=1" in out

    def test_no_raw_payload(self, capsys):
        print_confirmed_warning(_alert(), "", _config(repeat=1))
        out = capsys.readouterr().out
        assert "raw_payload" not in out
        assert "wallet" not in out


class TestFormatWarningLine:
    def test_contains_key_fields(self):
        line = format_warning_line(_alert(), "/tmp/alerts.jsonl")
        assert "confirmed_mining_live" in line
        assert "38341" in line
        assert "xmigr" in line
        assert "job=16" in line
        assert "submit=1" in line
        assert "assoc=1" in line

    def test_no_sensitive_data(self):
        line = format_warning_line(_alert())
        assert "raw_payload" not in line
        assert "wallet" not in line
        assert "job_id" not in line


class TestAppendWarningLog:
    def test_writes_file(self):
        tmpdir = tempfile.mkdtemp()
        log_path = os.path.join(tmpdir, "warnings.log")
        config = _config(warn_log=log_path)
        result = append_warning_log(_alert(), config, "/tmp/alerts.jsonl")
        assert result == log_path
        assert os.path.exists(log_path)
        with open(log_path) as f:
            content = f.read()
        assert "confirmed_mining_live" in content
        assert "38341" in content

    def test_fallback_on_permission_error(self):
        config = _config(warn_log="/root/no_permission/warnings.log")
        result = append_warning_log(_alert(), config)
        assert "/tmp/layerminer" in result
        assert os.path.exists(result)


class TestScanSummaryLastAlert:
    def test_last_alert_in_summary(self, capsys):
        summary = {
            "run_id": "abc12345", "raw_candidate_count": 1,
            "observation_eligible_count": 1, "weak_candidate_count": 0,
            "confirmed_candidate_count": 1, "pending_candidate_count": 0,
            "observed_count": 1, "observations_written": 1,
            "confirmed_alerts_written": 1,
            "confirmed_mining_count": 1, "protocol_suspicious_count": 0,
            "fallback_suspicious_count": 0,
            "last_alert_verdict": "confirmed_mining_live",
            "last_alert_pid": 38341, "last_alert_process": "xmigr",
        }
        print_scan_summary(summary)
        out = capsys.readouterr().out
        assert "last_alert=confirmed_mining_live" in out
        assert "pid=38341" in out

    def test_no_last_alert_when_empty(self, capsys):
        summary = {
            "run_id": "abc12345", "raw_candidate_count": 0,
            "observation_eligible_count": 0, "weak_candidate_count": 0,
            "confirmed_candidate_count": 0, "pending_candidate_count": 0,
            "observed_count": 0, "observations_written": 0,
            "confirmed_alerts_written": 0,
            "confirmed_mining_count": 0, "protocol_suspicious_count": 0,
            "fallback_suspicious_count": 0,
            "last_alert_verdict": "", "last_alert_pid": 0, "last_alert_process": "",
        }
        print_scan_summary(summary)
        out = capsys.readouterr().out
        assert "last_alert=" not in out


class TestMissingFields:
    def test_warning_no_crash(self, capsys):
        print_confirmed_warning({}, "", _config(repeat=1))
        out = capsys.readouterr().out
        assert "MINING WARNING" in out

    def test_format_no_crash(self):
        line = format_warning_line({})
        assert "verdict=" in line
