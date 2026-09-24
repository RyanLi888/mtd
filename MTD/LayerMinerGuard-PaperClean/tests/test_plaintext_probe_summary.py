"""Plaintext probe summary tests."""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layerminer.schema import MarkerSummary, VISIBILITY_PLAINTEXT


class TestPlaintextProbeSummary:
    def test_visibility_mode(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_PLAINTEXT)
        assert ms.visibility_mode == "plaintext_stratum"

    def test_default_counters_zero(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_PLAINTEXT)
        assert ms.job_marker_count == 0
        assert ms.submit_marker_count == 0
        assert ms.associated_submit_count == 0

    def test_raw_payload_always_false(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_PLAINTEXT)
        assert ms.raw_payload_saved is False

    def test_validate_passes(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_PLAINTEXT)
        ms.validate()

    def test_plaintext_probe_script_exists(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "probes", "plaintext_stratum_probe.py")
        assert os.path.exists(path)

    def test_fake_plaintext_pool_exists(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "workloads", "fake_plaintext_pool.py")
        assert os.path.exists(path)
