"""TLS probe summary tests."""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layerminer.schema import MarkerSummary, VISIBILITY_TLS


class TestTlsProbeSummary:
    def test_visibility_mode(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_TLS)
        assert ms.visibility_mode == "openssl_visible_tls"

    def test_default_counters_zero(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_TLS)
        assert ms.job_marker_count == 0
        assert ms.submit_marker_count == 0
        assert ms.associated_submit_count == 0

    def test_raw_payload_always_false(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_TLS)
        assert ms.raw_payload_saved is False

    def test_validate_passes(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_TLS)
        ms.validate()

    def test_tls_probe_script_exists(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "probes", "tls_openssl_probe.py")
        assert os.path.exists(path)

    def test_fake_tls_pool_exists(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "workloads", "fake_tls_pool.py")
        assert os.path.exists(path)
