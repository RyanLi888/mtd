"""Tests for stale candidate state cleanup."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.candidate_state import (
    update_candidate_state,
    load_candidate_state,
    save_candidate_state,
)


def _test_config(min_hits=2, ttl=900):
    tmpdir = tempfile.mkdtemp()
    return {
        "candidate": {"min_consecutive_hits": min_hits, "state_ttl_sec": ttl},
        "output": {"candidate_state_json": os.path.join(tmpdir, "state.json")},
    }


def _make_candidate(pid=1000, name="test", exe_hash="sha256:abc", create_time=1000.0):
    return {
        "pid": pid, "name": name, "score": 0.5,
        "reasons": ["high_cpu", "network_activity", "runtime_ok", "not_whitelisted"],
        "observation_eligible": True,
        "observation_priority": 50,
        "observation_block_reason": "",
        "process": {"exe_hash": exe_hash, "create_time": create_time, "identity_key": f"{pid}:{create_time:.3f}:{exe_hash}"},
    }


class TestStaleCandidatePurge:
    def test_old_candidate_removed_when_not_in_current(self):
        config = _test_config()
        cands = [_make_candidate(pid=100, create_time=100.0)]
        # Run 3 times to confirm
        for _ in range(3):
            update_candidate_state(cands, config)
        state = load_candidate_state(config)
        assert len(state) == 1

        # Now candidates change — old one should be purged
        new_cands = [_make_candidate(pid=200, create_time=200.0)]
        update_candidate_state(new_cands, config)
        state = load_candidate_state(config)
        assert len(state) == 1
        # Old PID 100 should be gone
        keys = list(state.keys())
        assert "200" in keys[0]

    def test_empty_candidates_clears_state(self):
        config = _test_config()
        cands = [_make_candidate()]
        for _ in range(3):
            update_candidate_state(cands, config)
        # Now empty
        update_candidate_state([], config)
        state = load_candidate_state(config)
        assert len(state) == 0

    def test_old_confirmed_not_reused(self):
        """Old PID with hit_count=2 should not produce confirmed when not in current candidates."""
        config = _test_config(min_hits=2)
        # Confirm old candidate
        old_cands = [_make_candidate(pid=100, create_time=100.0)]
        for _ in range(3):
            confirmed, pending, _ = update_candidate_state(old_cands, config)
        assert len(confirmed) == 1

        # Now only new candidate appears — old confirmed should be gone
        new_cands = [_make_candidate(pid=200, create_time=200.0)]
        confirmed, pending, _ = update_candidate_state(new_cands, config)
        # new_cands only has 1 hit, so should be pending
        assert len(confirmed) == 0
        assert len(pending) == 1

    def test_same_pid_different_create_time_is_different(self):
        """Same PID with different create_time should be treated as different processes."""
        config = _test_config(min_hits=2)
        cands_v1 = [_make_candidate(pid=100, create_time=100.0)]
        update_candidate_state(cands_v1, config)

        # Same PID, different create_time (process restarted)
        cands_v2 = [_make_candidate(pid=100, create_time=999.0)]
        confirmed, pending, state = update_candidate_state(cands_v2, config)
        # Should be pending (1 hit), not confirmed
        assert len(confirmed) == 0
        assert len(pending) == 1
        # Old entry should be purged, new entry should be present
        assert len(state) == 1
