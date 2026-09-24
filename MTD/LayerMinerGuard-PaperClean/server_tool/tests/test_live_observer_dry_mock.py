"""Tests for live_observer module — mock/dry tests (no real probes)."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.live_observer import _get_cpu_avg


def _base_config():
    return {
        "agent": {"dry_run": False, "observe_duration_sec": 90, "cooldown_sec": 600},
        "observer": {
            "enable_plaintext_probe": True,
            "enable_tls_probe": True,
            "enable_cpu_telemetry": True,
            "dry_run_only": False,
            "plaintext_probe_duration_sec": 5,
            "tls_probe_duration_sec": 5,
            "probe_timeout_sec": 10,
        },
        "verdict": {"compute_cpu_threshold_percent": 30},
    }


class TestGetCpuAvg:
    def test_returns_float(self):
        result = _get_cpu_avg(1, 2)
        assert isinstance(result, float)

    def test_nonexistent_pid(self):
        result = _get_cpu_avg(999999, 2)
        assert result == 0.0


class TestObserverOutputFormat:
    """Test that observe_candidate_live returns correct format (without running real probes)."""

    def test_dead_pid_returns_error(self):
        from server_tool.layerminer_server.live_observer import observe_candidate_live
        cand = {
            "pid": 999999, "name": "test",
            "process": {"has_libssl": False, "exe_hash": "sha256:abc"},
        }
        result = observe_candidate_live(cand, _base_config())
        assert result.get("error") == "pid_not_found"
        assert result["compute_evidence_present"] is False

    def test_privacy_fields_present(self):
        from server_tool.layerminer_server.live_observer import observe_candidate_live
        cand = {
            "pid": 999999, "name": "test",
            "process": {"has_libssl": False, "exe_hash": "sha256:abc"},
        }
        result = observe_candidate_live(cand, _base_config())
        privacy = result.get("privacy", {})
        assert privacy.get("raw_payload_saved") is False
        assert privacy.get("wallet_saved") is False
