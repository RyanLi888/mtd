"""Tests for observer_scheduler module."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.observer_scheduler import build_observation_plan


def _make_candidate(pid=1000, reasons=None, libssl=False, remote=5):
    return {
        "pid": pid,
        "name": "suspicious",
        "score": 0.8,
        "reasons": reasons or ["high_cpu", "network_activity", "runtime_ok", "not_whitelisted"],
        "process": {
            "pid": pid, "has_libssl": libssl, "remote_count": remote,
        },
    }


def _base_config():
    return {
        "observer": {
            "enable_plaintext_probe": True,
            "enable_tls_probe": True,
            "enable_cpu_telemetry": True,
            "max_concurrent_observations": 1,
            "max_prefix_bytes": 384,
            "dry_run_only": True,
        }
    }


class TestBuildObservationPlan:
    def test_returns_dict(self):
        plan = build_observation_plan(_make_candidate(), _base_config())
        assert isinstance(plan, dict)

    def test_dry_run_flag(self):
        plan = build_observation_plan(_make_candidate(), _base_config())
        assert plan["dry_run"] is True

    def test_no_real_probes_in_dry_run(self):
        plan = build_observation_plan(_make_candidate(), _base_config())
        assert plan["would_run_plaintext_probe"] is False
        assert plan["would_run_tls_probe"] is False

    def test_observe_tls_when_libssl(self):
        cand = _make_candidate(libssl=True)
        plan = build_observation_plan(cand, _base_config())
        assert plan["would_observe_tls"] is True
        assert "would_observe_tls" in plan["reason"]

    def test_observe_plaintext_when_network(self):
        cand = _make_candidate(remote=5)
        plan = build_observation_plan(cand, _base_config())
        assert plan["would_observe_plaintext"] is True

    def test_visibility_hint_libssl_and_network(self):
        cand = _make_candidate(libssl=True, remote=5)
        plan = build_observation_plan(cand, _base_config())
        assert plan["visibility_hint"] == "openssl_visible_tls_or_plaintext"

    def test_visibility_hint_no_visibility(self):
        cand = _make_candidate(libssl=False, remote=0)
        plan = build_observation_plan(cand, _base_config())
        assert plan["visibility_hint"] == "no_visibility"
