"""Tests for candidate_state module."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.candidate_state import (
    load_candidate_state,
    save_candidate_state,
    update_candidate_state,
)


def _test_config():
    """Create a test config with temporary paths."""
    tmpdir = tempfile.mkdtemp()
    return {
        "candidate": {
            "min_consecutive_hits": 3,
            "state_ttl_sec": 900,
        },
        "output": {
            "candidate_state_json": os.path.join(tmpdir, "candidate_state.json"),
            "alerts_jsonl": os.path.join(tmpdir, "alerts.jsonl"),
        },
    }


def _make_candidate(pid=1000, name="test", exe_hash="sha256:abc"):
    return {
        "pid": pid,
        "name": name,
        "score": 0.5,
        "reasons": ["high_cpu", "network_activity", "runtime_ok", "not_whitelisted"],
        "observation_eligible": True,
        "observation_priority": 50,
        "observation_block_reason": "",
        "process": {"exe_hash": exe_hash, "create_time": float(pid),
                     "identity_key": f"{pid}:{float(pid):.3f}:{exe_hash}"},
    }


class TestLoadSave:
    def test_load_empty(self):
        config = _test_config()
        state = load_candidate_state(config)
        assert state == {}

    def test_save_and_load(self):
        config = _test_config()
        state = {"test:key": {"pid": 1, "hit_count": 2}}
        save_candidate_state(state, config)
        loaded = load_candidate_state(config)
        assert loaded["test:key"]["hit_count"] == 2


class TestUpdateCandidateState:
    def test_first_appearance_is_pending(self):
        config = _test_config()
        cands = [_make_candidate()]
        confirmed, pending, state = update_candidate_state(cands, config)
        assert len(confirmed) == 0
        assert len(pending) == 1
        assert pending[0]["hit_count"] == 1

    def test_third_appearance_is_confirmed(self):
        config = _test_config()
        cands = [_make_candidate()]
        # Run 3 times
        for _ in range(2):
            update_candidate_state(cands, config)
        confirmed, pending, state = update_candidate_state(cands, config)
        assert len(confirmed) == 1
        assert confirmed[0]["hit_count"] == 3
        assert len(pending) == 0

    def test_different_candidate_stays_pending(self):
        config = _test_config()
        cands = [_make_candidate(pid=1001, exe_hash="sha256:def")]
        for _ in range(2):
            update_candidate_state(cands, config)
        # Different candidate
        cands2 = [_make_candidate(pid=1002, exe_hash="sha256:ghi")]
        confirmed, pending, state = update_candidate_state(cands2, config)
        assert len(confirmed) == 0
        assert len(pending) == 1

    def test_disappeared_candidate_resets(self):
        config = _test_config()
        cands = [_make_candidate()]
        for _ in range(3):
            update_candidate_state(cands, config)
        # Candidate disappears
        confirmed, pending, state = update_candidate_state([], config)
        # Re-appears
        confirmed, pending, state = update_candidate_state(cands, config)
        assert len(confirmed) == 0  # reset, needs 3 more
        assert pending[0]["hit_count"] == 1

    def test_custom_min_consecutive_hits(self):
        config = _test_config()
        config["candidate"]["min_consecutive_hits"] = 1
        cands = [_make_candidate()]
        confirmed, pending, state = update_candidate_state(cands, config)
        assert len(confirmed) == 1
