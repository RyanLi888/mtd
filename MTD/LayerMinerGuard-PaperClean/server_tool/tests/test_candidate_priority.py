"""Tests for candidate priority ordering."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.candidate_selector import select_candidates
from server_tool.layerminer_server.candidate_state import update_candidate_state


def _make_process(pid=1000, name="test", cpu=90.0, runtime=120, remote=5,
                  libssl=False, exe_path="/tmp/test"):
    return {
        "pid": pid, "ppid": 1, "name": name, "exe_path": exe_path,
        "exe_hash": f"sha256:{pid:04d}", "create_time": float(pid),
        "identity_key": f"{pid}:{float(pid):.3f}:sha256:{pid:04d}",
        "username": "nobody", "is_root_process": False,
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
            "whitelist_names": [], "whitelist_paths": [],
            "min_consecutive_hits": 2, "state_ttl_sec": 900,
            "require_strong_observation_signal": True,
            "observe_network_only_candidates": False,
        },
        "output": {"candidate_state_json": os.path.join(tempfile.mkdtemp(), "state.json"),
                   "alerts_jsonl": os.path.join(tempfile.mkdtemp(), "alerts.jsonl")},
    }


class TestPriorityOrdering:
    def test_name_suspicious_high_cpu_first(self):
        """name_suspicious + high_cpu should be first (priority 100)."""
        procs = [
            _make_process(pid=100, name="mystery", cpu=95.0),   # high_cpu only
            _make_process(pid=200, name="xmrig", cpu=10.0),     # name_suspicious only
            _make_process(pid=300, name="xmrig", cpu=95.0),     # name_suspicious + high_cpu
        ]
        result = select_candidates(procs, _base_config())
        assert result[0]["pid"] == 300  # name_suspicious + high_cpu first
        assert result[0]["observation_priority"] == 100

    def test_name_suspicious_before_high_cpu(self):
        """name_suspicious (80) > high_cpu (50)."""
        procs = [
            _make_process(pid=100, name="mystery", cpu=95.0),   # high_cpu
            _make_process(pid=200, name="xmrig", cpu=10.0),     # name_suspicious
        ]
        result = select_candidates(procs, _base_config())
        assert result[0]["pid"] == 200  # name_suspicious first

    def test_weak_candidates_last(self):
        """Weak (network-only) candidates should be last."""
        procs = [
            _make_process(pid=100, name="claude", cpu=10.0),    # weak
            _make_process(pid=200, name="xmrig", cpu=95.0),     # strong
            _make_process(pid=300, name="ssh-agent", cpu=5.0),  # weak
        ]
        result = select_candidates(procs, _base_config())
        # Strong first, weak last
        assert result[0]["observation_eligible"] is True
        assert result[-1]["observation_eligible"] is False


class TestCandidateStateEligibility:
    def test_weak_candidate_not_confirmed(self):
        """Weak candidates with hit_count >= min_hits should NOT be confirmed."""
        config = _base_config()
        weak_cand = {
            "pid": 100, "name": "claude", "score": 0.5,
            "reasons": ["network_activity", "runtime_ok", "not_whitelisted"],
            "observation_eligible": False,
            "observation_priority": 0,
            "observation_block_reason": "weak_network_only_signal",
            "process": {"exe_hash": "sha256:100", "create_time": 100.0,
                        "identity_key": "100:100.000:sha256:100"},
        }
        # Run 3 times to get hit_count >= 2
        for _ in range(3):
            confirmed, pending, _ = update_candidate_state([weak_cand], config)
        # Should NOT be confirmed even with hit_count=3
        assert len(confirmed) == 0
        assert len(pending) == 1

    def test_strong_candidate_confirmed(self):
        """Strong candidates with hit_count >= min_hits should be confirmed."""
        config = _base_config()
        strong_cand = {
            "pid": 200, "name": "xmrig", "score": 0.9,
            "reasons": ["name_suspicious", "high_cpu", "network_activity", "runtime_ok"],
            "observation_eligible": True,
            "observation_priority": 100,
            "observation_block_reason": "",
            "process": {"exe_hash": "sha256:200", "create_time": 200.0,
                        "identity_key": "200:200.000:sha256:200"},
        }
        for _ in range(3):
            confirmed, pending, _ = update_candidate_state([strong_cand], config)
        assert len(confirmed) == 1
        assert confirmed[0]["name"] == "xmrig"
