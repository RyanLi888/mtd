"""Tests for candidate identity key."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.process_scanner import build_process_identity_key
from server_tool.layerminer_server.candidate_state import candidate_identity_key


class TestBuildIdentityKey:
    def test_contains_pid(self):
        key = build_process_identity_key(1234, 1000.0, "sha256:abc")
        assert "1234" in key

    def test_contains_create_time(self):
        key = build_process_identity_key(1234, 1000.123, "sha256:abc")
        assert "1000.123" in key

    def test_contains_exe_hash(self):
        key = build_process_identity_key(1234, 1000.0, "sha256:abc")
        assert "sha256:abc" in key

    def test_same_params_same_key(self):
        k1 = build_process_identity_key(1234, 1000.0, "sha256:abc")
        k2 = build_process_identity_key(1234, 1000.0, "sha256:abc")
        assert k1 == k2

    def test_different_create_time_different_key(self):
        k1 = build_process_identity_key(1234, 1000.0, "sha256:abc")
        k2 = build_process_identity_key(1234, 2000.0, "sha256:abc")
        assert k1 != k2

    def test_different_pid_different_key(self):
        k1 = build_process_identity_key(100, 1000.0, "sha256:abc")
        k2 = build_process_identity_key(200, 1000.0, "sha256:abc")
        assert k1 != k2

    def test_empty_exe_hash_uses_name(self):
        key = build_process_identity_key(1234, 1000.0, "", "xmigr")
        assert "xmigr" in key

    def test_empty_all_uses_unknown(self):
        key = build_process_identity_key(1234, 1000.0, "", "")
        assert "unknown" in key


class TestCandidateIdentityKey:
    def test_from_process_identity_key(self):
        cand = {"pid": 1234, "name": "test", "process": {"identity_key": "1234:1000.0:sha256:abc"}}
        assert candidate_identity_key(cand) == "1234:1000.0:sha256:abc"

    def test_fallback_to_build(self):
        cand = {"pid": 1234, "name": "test", "process": {"create_time": 1000.0, "exe_hash": "sha256:abc"}}
        key = candidate_identity_key(cand)
        assert "1234" in key
        assert "sha256:abc" in key
