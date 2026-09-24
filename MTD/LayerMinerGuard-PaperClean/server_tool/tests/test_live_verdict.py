"""Tests for live_verdict module."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.live_verdict import decide_live_verdict


def _base_config():
    return {
        "verdict": {
            "require_compute_evidence": True,
            "compute_cpu_threshold_percent": 30,
            "confirmed_require_job": True,
            "confirmed_require_submit": True,
            "confirmed_require_association": True,
            "suspicious_allow_job_only": True,
        }
    }


def _make_obs(compute=True, plain_job=0, plain_submit=0, plain_assoc=0,
              tls_job=0, tls_submit=0, tls_assoc=0):
    return {
        "compute_evidence_present": compute,
        "plaintext": {
            "enabled": True,
            "job_marker_count": plain_job,
            "submit_marker_count": plain_submit,
            "associated_submit_count": plain_assoc,
        },
        "tls": {
            "enabled": True,
            "job_marker_count": tls_job,
            "submit_marker_count": tls_submit,
            "associated_submit_count": tls_assoc,
        },
    }


class TestConfirmedMining:
    def test_full_evidence_confirmed(self):
        obs = _make_obs(plain_job=5, plain_submit=2, plain_assoc=1)
        v = decide_live_verdict(obs, _base_config())
        assert v["verdict"] == "confirmed_mining_live"
        assert v["confidence"] == "high"
        assert "compute_evidence_present" in v["reasons"]
        assert "job_marker_seen" in v["reasons"]
        assert "submit_marker_seen" in v["reasons"]
        assert "association_seen" in v["reasons"]

    def test_tls_full_evidence_confirmed(self):
        obs = _make_obs(tls_job=3, tls_submit=1, tls_assoc=1)
        v = decide_live_verdict(obs, _base_config())
        assert v["verdict"] == "confirmed_mining_live"

    def test_mixed_plain_tls_confirmed(self):
        obs = _make_obs(plain_job=2, tls_submit=1, tls_assoc=1)
        v = decide_live_verdict(obs, _base_config())
        assert v["verdict"] == "confirmed_mining_live"


class TestProtocolSuspicious:
    def test_job_only_suspicious(self):
        obs = _make_obs(plain_job=3)
        v = decide_live_verdict(obs, _base_config())
        assert v["verdict"] == "protocol_suspicious"
        assert v["confidence"] == "medium"

    def test_job_and_submit_no_assoc(self):
        obs = _make_obs(plain_job=3, plain_submit=1)
        v = decide_live_verdict(obs, _base_config())
        assert v["verdict"] == "protocol_suspicious"


class TestFallbackSuspicious:
    def test_compute_only(self):
        obs = _make_obs(compute=True)
        v = decide_live_verdict(obs, _base_config())
        assert v["verdict"] == "fallback_suspicious"
        assert v["confidence"] == "low"


class TestVisibilityBoundary:
    def test_no_dynamic_libssl(self):
        """When plaintext enabled, TLS not enabled, no libssl."""
        obs = _make_obs(compute=True)
        obs["plaintext"]["enabled"] = True
        obs["tls"]["enabled"] = False
        obs["has_libssl"] = False
        v = decide_live_verdict(obs, _base_config())
        assert v["visibility_boundary"] == "no_dynamic_libssl_mapping"
        assert "visibility_boundary:no_dynamic_libssl_mapping" in v["reasons"]

    def test_encrypted_or_no_markers(self):
        """When both probes enabled but no markers."""
        obs = _make_obs(compute=True)
        obs["plaintext"]["enabled"] = True
        obs["tls"]["enabled"] = True
        v = decide_live_verdict(obs, _base_config())
        assert v["visibility_boundary"] == "encrypted_or_no_markers"

    def test_none_when_markers_found(self):
        """When markers found, visibility_boundary is None."""
        obs = _make_obs(compute=True, plain_job=5)
        obs["plaintext"]["enabled"] = True
        v = decide_live_verdict(obs, _base_config())
        assert v["visibility_boundary"] is None


class TestBenign:
    def test_no_compute(self):
        obs = _make_obs(compute=False)
        v = decide_live_verdict(obs, _base_config())
        assert v["verdict"] == "benign_or_unconfirmed"
        assert v["confidence"] == "none"

    def test_no_evidence(self):
        obs = {"compute_evidence_present": False, "plaintext": {"enabled": False}, "tls": {"enabled": False}}
        v = decide_live_verdict(obs, _base_config())
        assert v["verdict"] == "benign_or_unconfirmed"
