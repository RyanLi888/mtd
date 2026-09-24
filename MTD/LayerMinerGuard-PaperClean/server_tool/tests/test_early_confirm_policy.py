"""Tests for early confirm policy and probe CLI."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestEarlyConfirmConfig:
    def test_live_yaml_has_early_confirm(self):
        import yaml
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml")
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f)
            ec = config.get("observer", {}).get("early_confirm", {})
            assert ec.get("enabled") is True
            assert ec.get("check_interval_sec") == 5
            assert ec.get("min_job_markers") == 1
            assert ec.get("min_submit_markers") == 1
            assert ec.get("min_associated_submits") == 1


class TestProbeEarlyConfirmCLI:
    def test_plaintext_probe_has_early_args(self):
        """Check plaintext probe accepts --early-confirm args."""
        import subprocess
        probe = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "probes", "plaintext_stratum_probe.py")
        result = subprocess.run(
            ["python3", probe, "--help"],
            capture_output=True, text=True)
        assert "--early-confirm" in result.stdout
        assert "--early-check-interval" in result.stdout
        assert "--early-min-job" in result.stdout

    def test_tls_probe_has_early_args(self):
        """Check TLS probe accepts --early-confirm args."""
        import subprocess
        probe = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "probes", "tls_openssl_probe.py")
        result = subprocess.run(
            ["python3", probe, "--help"],
            capture_output=True, text=True)
        assert "--early-confirm" in result.stdout
        assert "--early-check-interval" in result.stdout


class TestProbeSummaryFields:
    def test_plaintext_output_has_early_fields(self):
        """Probe output JSON should contain early_confirmed and actual_observe_duration_sec."""
        import json, tempfile, subprocess
        probe = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "probes", "plaintext_stratum_probe.py")
        # Just check the help/output format by inspecting the source
        with open(probe) as f:
            content = f.read()
        assert "early_confirmed" in content
        assert "actual_observe_duration_sec" in content

    def test_tls_output_has_early_fields(self):
        """TLS probe output JSON should contain early_confirmed fields."""
        import json
        probe = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "probes", "tls_openssl_probe.py")
        with open(probe) as f:
            content = f.read()
        assert "early_confirmed" in content
        assert "actual_observe_duration_sec" in content
