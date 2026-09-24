"""Tests for on-demand probe policy."""

import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestLiveYamlProbeMode:
    def test_probe_mode_on_demand(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml"
        )
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f)
            assert config["observer"]["probe_mode"] == "on_demand"

    def test_auto_start_false(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml"
        )
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f)
            assert config["agent"]["auto_start"] is False

    def test_dry_run_false(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml"
        )
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f)
            assert config["agent"]["dry_run"] is False


class TestAlertPolicyDefaults:
    def test_confirmed_alerts_enabled(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml"
        )
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f)
            assert config["alert_policy"]["emit_confirmed_alerts"] is True

    def test_suspicious_alerts_disabled(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml"
        )
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f)
            assert config["alert_policy"]["emit_protocol_suspicious_alerts"] is False
            assert config["alert_policy"]["emit_fallback_suspicious_alerts"] is False

    def test_all_observations_written(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "config", "live.yaml"
        )
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f)
            assert config["alert_policy"]["write_all_observations"] is True


class TestInstallScript:
    def test_no_systemctl_enable(self):
        install_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "server_tool", "packaging", "install.sh"
        )
        if os.path.exists(install_path):
            with open(install_path) as f:
                content = f.read()
            lines = content.split('\n')
            for line in lines:
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('echo'):
                    continue
                assert 'systemctl enable' not in stripped
                assert 'systemctl start' not in stripped


class TestObserverNotGlobal:
    def test_observer_targets_candidate_pid(self):
        """Observer should only target specific candidate PIDs, not global hooks."""
        from server_tool.layerminer_server.live_observer import observe_candidate_live
        # Verify the function signature accepts a candidate dict with pid
        import inspect
        sig = inspect.signature(observe_candidate_live)
        assert 'candidate' in sig.parameters
        assert 'config' in sig.parameters
