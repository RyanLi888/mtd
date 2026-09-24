"""Tests for lmgctl cleanup commands."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.console_ui import format_warning_line


def _tmp_config(tmpdir):
    return {
        "agent": {"mode": "manual", "scan_interval_sec": 10, "observe_duration_sec": 300,
                  "default_action": "alert_only", "auto_start": False},
        "observer": {"probe_mode": "on_demand"},
        "alert_policy": {"emit_confirmed_alerts": True, "emit_protocol_suspicious_alerts": False},
        "console": {"warning_log": os.path.join(tmpdir, "warnings.log"),
                    "alert_repeat_count": 3, "alert_repeat_interval_sec": 0, "terminal_bell": False},
        "output": {"alerts_jsonl": os.path.join(tmpdir, "alerts.jsonl"),
                   "candidate_state_json": os.path.join(tmpdir, "state.json"),
                   "observation_dir": os.path.join(tmpdir, "observations")},
    }


class TestClearWarnings:
    def test_clear_warnings(self):
        tmpdir = tempfile.mkdtemp()
        config = _tmp_config(tmpdir)
        warn_path = config["console"]["warning_log"]
        # Create warnings file
        with open(warn_path, 'w') as f:
            f.write("line1\nline2\nline3\n")
        assert os.path.exists(warn_path)
        # Import and call
        from server_tool.bin.lmgctl import cmd_clear_warnings
        cmd_clear_warnings(config)
        assert os.path.exists(warn_path)
        with open(warn_path) as f:
            assert f.read() == ""


class TestClearObservations:
    def test_clear_observations(self):
        tmpdir = tempfile.mkdtemp()
        config = _tmp_config(tmpdir)
        obs_dir = config["output"]["observation_dir"]
        os.makedirs(obs_dir, exist_ok=True)
        # Create observation files
        for i in range(3):
            with open(os.path.join(obs_dir, f"obs_{i}.json"), 'w') as f:
                json.dump({"test": i}, f)
        assert len(os.listdir(obs_dir)) == 3
        # Clear
        from server_tool.bin.lmgctl import cmd_clear_observations
        cmd_clear_observations(config)
        assert len(os.listdir(obs_dir)) == 0


class TestClearAll:
    def test_clear_all(self):
        tmpdir = tempfile.mkdtemp()
        config = _tmp_config(tmpdir)
        # Create all files
        alerts_path = config["output"]["alerts_jsonl"]
        state_path = config["output"]["candidate_state_json"]
        warn_path = config["console"]["warning_log"]
        obs_dir = config["output"]["observation_dir"]
        os.makedirs(obs_dir, exist_ok=True)
        with open(alerts_path, 'w') as f:
            f.write('{"test":1}\n')
        with open(state_path, 'w') as f:
            json.dump({"k": "v"}, f)
        with open(warn_path, 'w') as f:
            f.write("warning\n")
        with open(os.path.join(obs_dir, "obs.json"), 'w') as f:
            json.dump({}, f)
        # Clear all
        from server_tool.bin.lmgctl import cmd_clear_all
        cmd_clear_all(config)
        assert os.path.exists(alerts_path)
        with open(alerts_path) as f:
            assert f.read() == ""


class TestWarnings:
    def test_warnings_display(self, capsys):
        tmpdir = tempfile.mkdtemp()
        config = _tmp_config(tmpdir)
        warn_path = config["console"]["warning_log"]
        with open(warn_path, 'w') as f:
            f.write("warning1\nwarning2\n")
        from server_tool.bin.lmgctl import cmd_warnings
        cmd_warnings(config)
        out = capsys.readouterr().out
        assert "warning1" in out
        assert "warning2" in out


class TestStatusWarnings:
    def test_status_shows_warnings_info(self, capsys):
        tmpdir = tempfile.mkdtemp()
        config = _tmp_config(tmpdir)
        warn_path = config["console"]["warning_log"]
        with open(warn_path, 'w') as f:
            f.write("line1\nline2\n")
        from server_tool.bin.lmgctl import cmd_status
        cmd_status(config)
        out = capsys.readouterr().out
        assert "Warnings file:" in out
        assert "Total warnings: 2" in out


class TestFormatWarningLine:
    def test_process_name_preserved(self):
        """process_name=xmrig should appear as process=xmrig, not xmigr."""
        alert = {"process_name": "xmrig", "verdict": "confirmed_mining_live", "pid": 1234,
                 "evidence": {"job_marker_count": 10, "submit_marker_count": 1, "associated_submit_count": 1}}
        line = format_warning_line(alert)
        assert "process=xmrig" in line
        assert "xmigr" not in line.replace("process=xmrig", "")

    def test_early_confirmed_in_line(self):
        alert = {"process_name": "xmrig", "verdict": "confirmed_mining_live", "pid": 1234,
                 "evidence": {"job_marker_count": 10, "submit_marker_count": 1, "associated_submit_count": 1},
                 "observation": {"early_confirmed": True, "actual_observe_duration_sec": 83.2}}
        line = format_warning_line(alert)
        assert "early_confirmed=true" in line
        assert "actual_duration=83.2s" in line

    def test_no_sensitive_data(self):
        alert = {"process_name": "xmrig", "verdict": "confirmed_mining_live",
                 "raw_payload": "secret", "wallet": "42sx...", "job_id": "abc"}
        line = format_warning_line(alert)
        assert "raw_payload" not in line
        assert "wallet" not in line
        assert "job_id" not in line
