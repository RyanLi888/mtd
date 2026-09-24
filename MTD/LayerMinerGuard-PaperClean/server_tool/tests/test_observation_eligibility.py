"""Tests for observation eligibility rules."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.candidate_selector import (
    _compute_observation_eligibility,
    select_candidates,
)


class TestObservationEligibility:
    def test_weak_network_only_not_eligible(self):
        """network_activity + runtime_ok only → not eligible."""
        reasons = ["network_activity", "runtime_ok", "not_whitelisted"]
        eligible, priority, block = _compute_observation_eligibility(reasons)
        assert eligible is False
        assert block == "weak_network_only_signal"

    def test_name_suspicious_eligible(self):
        """name_suspicious + network_activity + runtime_ok → eligible."""
        reasons = ["name_suspicious", "network_activity", "runtime_ok", "not_whitelisted"]
        eligible, priority, block = _compute_observation_eligibility(reasons)
        assert eligible is True
        assert priority == 80

    def test_high_cpu_eligible(self):
        """high_cpu + network_activity + runtime_ok → eligible."""
        reasons = ["high_cpu", "network_activity", "runtime_ok", "not_whitelisted"]
        eligible, priority, block = _compute_observation_eligibility(reasons)
        assert eligible is True
        assert priority == 50

    def test_name_suspicious_high_cpu_highest_priority(self):
        """name_suspicious + high_cpu → priority 100."""
        reasons = ["name_suspicious", "high_cpu", "network_activity", "runtime_ok"]
        eligible, priority, block = _compute_observation_eligibility(reasons)
        assert eligible is True
        assert priority == 100

    def test_libssl_high_cpu_eligible(self):
        """has_libssl + high_cpu + network_activity + runtime_ok → eligible."""
        reasons = ["has_libssl", "high_cpu", "network_activity", "runtime_ok"]
        eligible, priority, block = _compute_observation_eligibility(reasons)
        assert eligible is True
        assert priority == 70

    def test_libssl_no_high_cpu_not_eligible(self):
        """has_libssl + network_activity but no high_cpu → not eligible."""
        reasons = ["has_libssl", "network_activity", "runtime_ok"]
        eligible, priority, block = _compute_observation_eligibility(reasons)
        assert eligible is False

    def test_no_network_not_eligible(self):
        """No network → not eligible."""
        reasons = ["high_cpu", "runtime_ok"]
        eligible, priority, block = _compute_observation_eligibility(reasons)
        assert eligible is False

    def test_no_runtime_not_eligible(self):
        """No runtime → not eligible."""
        reasons = ["high_cpu", "network_activity"]
        eligible, priority, block = _compute_observation_eligibility(reasons)
        assert eligible is False


def _make_process(pid=1000, name="test", cpu=90.0, runtime=120, remote=5,
                  libssl=False, exe_path="/tmp/test", username="nobody"):
    return {
        "pid": pid, "ppid": 1, "name": name, "exe_path": exe_path,
        "exe_hash": "sha256:abc", "create_time": 1000.0,
        "identity_key": f"{pid}:1000.000:sha256:abc",
        "username": username, "is_root_process": username == "root",
        "system_service_like": False, "cpu_percent": cpu,
        "memory_rss": 1024*1024, "runtime_sec": runtime,
        "connection_count": 10, "remote_count": remote,
        "has_libssl": libssl, "kernel_thread": False,
        "cmdline_hash": "def", "cmdline_preview_sanitized": "/tmp/test",
    }


def _base_config():
    return {
        "candidate": {
            "min_cpu_percent": 80, "min_runtime_sec": 60,
            "require_network": True, "max_candidates_per_scan": 10,
            "ignore_kernel_threads": True, "ignore_system_services": True,
            "ignore_service_users": ["root"],
            "whitelist_names": ["systemd", "sshd"],
            "whitelist_paths": ["/usr/lib/systemd/"],
            "require_strong_observation_signal": True,
            "observe_network_only_candidates": False,
        }
    }


class TestCandidateSelection:
    def test_claude_weak_not_eligible(self):
        """Claude with network + runtime but no high_cpu → weak, not eligible."""
        procs = [_make_process(pid=5688, name="claude", cpu=10.0, runtime=120, remote=5)]
        result = select_candidates(procs, _base_config())
        assert len(result) == 1
        assert result[0]["observation_eligible"] is False
        assert result[0]["observation_block_reason"] == "weak_network_only_signal"

    def test_xmrig_eligible(self):
        """xmrig with name_suspicious + network → eligible."""
        procs = [_make_process(pid=1234, name="xmrig", cpu=90.0, runtime=120, remote=5)]
        result = select_candidates(procs, _base_config())
        assert len(result) == 1
        assert result[0]["observation_eligible"] is True
        assert "name_suspicious" in result[0]["reasons"]

    def test_high_cpu_eligible(self):
        """Process with high_cpu + network → eligible."""
        procs = [_make_process(pid=1234, name="mystery", cpu=95.0, runtime=120, remote=5)]
        result = select_candidates(procs, _base_config())
        assert len(result) == 1
        assert result[0]["observation_eligible"] is True

    def test_xmigr_before_claude(self):
        """xmrig should be sorted before claude."""
        procs = [
            _make_process(pid=5688, name="claude", cpu=10.0, runtime=120, remote=5),
            _make_process(pid=1234, name="xmrig", cpu=90.0, runtime=120, remote=5),
        ]
        result = select_candidates(procs, _base_config())
        assert result[0]["name"] == "xmrig"
        assert result[1]["name"] == "claude"
