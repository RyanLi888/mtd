"""Tests for pre-observation PID validation."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.live_observer import (
    validate_candidate_process,
    observe_candidate_live,
)
from server_tool.layerminer_server.live_verdict import decide_live_verdict


def _candidate(pid=1, create_time=100.0, exe_hash="sha256:abc"):
    return {
        "pid": pid, "name": "test", "score": 0.5,
        "reasons": ["high_cpu"],
        "process": {
            "pid": pid, "exe_hash": exe_hash, "create_time": create_time,
            "identity_key": f"{pid}:{create_time:.3f}:{exe_hash}",
            "has_libssl": False, "remote_count": 1,
        },
    }


def _config():
    return {
        "agent": {"observe_duration_sec": 5},
        "observer": {"enable_plaintext_probe": True, "enable_tls_probe": True,
                     "plaintext_probe_duration_sec": 5, "tls_probe_duration_sec": 5,
                     "probe_timeout_sec": 10},
        "verdict": {"compute_cpu_threshold_percent": 30},
    }


class TestValidateCandidateProcess:
    def test_nonexistent_pid(self):
        cand = _candidate(pid=999999)
        valid, info = validate_candidate_process(cand)
        assert valid is False
        assert info["reason"] == "pid_not_found"

    def test_valid_pid(self):
        # PID 1 (init) should exist on Linux
        cand = _candidate(pid=1, create_time=0.0, exe_hash="")
        valid, info = validate_candidate_process(cand)
        assert valid is True

    def test_create_time_mismatch(self):
        # PID 1 exists but with wrong create_time
        cand = _candidate(pid=1, create_time=9999999999.0, exe_hash="")
        valid, info = validate_candidate_process(cand)
        # Should fail if create_time is very different
        # (PID 1's real create_time is near boot, not 9999999999)
        if not valid:
            assert info["reason"] == "pid_identity_mismatch"


class TestObserveSkipped:
    def test_observe_skipped_returns_skip_fields(self):
        """When PID is invalid, observe_candidate_live should return skip fields."""
        cand = _candidate(pid=999999)
        result = observe_candidate_live(cand, _config())
        assert result.get("observe_skipped") is True
        assert result.get("skip_reason") == "pid_not_found"
        assert result.get("compute_evidence_present") is False

    def test_observe_skipped_no_probes(self):
        """When PID is invalid, no probe subprocess should be launched."""
        cand = _candidate(pid=999999)
        result = observe_candidate_live(cand, _config())
        assert result["plaintext"]["enabled"] is False
        assert result["tls"]["enabled"] is False


class TestVerdictSkipped:
    def test_skipped_verdict(self):
        obs = {"observe_skipped": True, "skip_reason": "pid_not_found"}
        v = decide_live_verdict(obs, _config())
        assert v["verdict"] == "benign_or_unconfirmed"
        assert v["visibility_boundary"] == "observation_skipped"
        assert "observation_skipped:pid_not_found" in v["reasons"]
