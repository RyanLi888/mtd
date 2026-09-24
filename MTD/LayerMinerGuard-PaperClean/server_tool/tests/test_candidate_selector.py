"""Tests for candidate_selector module."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.candidate_selector import select_candidates


def _make_process(pid=1000, name="suspicious", cpu=80.0, runtime=60,
                  remote=5, libssl=False, exe_path="/usr/bin/suspicious",
                  kernel_thread=False, system_service_like=False, username="nobody"):
    return {
        "pid": pid, "ppid": 1, "name": name, "exe_path": exe_path,
        "exe_hash": "sha256:abc123", "username": username,
        "is_root_process": username == "root",
        "system_service_like": system_service_like,
        "cpu_percent": cpu, "memory_rss": 1024 * 1024,
        "runtime_sec": runtime, "connection_count": 10,
        "remote_count": remote, "has_libssl": libssl,
        "kernel_thread": kernel_thread, "cmdline_hash": "def456",
        "cmdline_preview_sanitized": "/usr/bin/suspicious --pool ...",
    }


def _base_config():
    return {
        "candidate": {
            "min_cpu_percent": 80,
            "min_runtime_sec": 60,
            "require_network": True,
            "max_candidates_per_scan": 10,
            "ignore_kernel_threads": True,
            "ignore_system_services": True,
            "ignore_service_users": ["root", "avahi"],
            "whitelist_names": ["systemd", "sshd", "dockerd"],
            "whitelist_paths": ["/usr/lib/systemd/", "/usr/sbin/"],
        }
    }


class TestSelectCandidates:
    def test_returns_list(self):
        result = select_candidates([], _base_config())
        assert isinstance(result, list)

    def test_selects_high_cpu_network_process(self):
        procs = [_make_process(cpu=90, runtime=120, remote=5)]
        result = select_candidates(procs, _base_config())
        assert len(result) == 1
        assert "high_cpu" in result[0]["reasons"]
        assert "network_activity" in result[0]["reasons"]

    def test_rejects_whitelist_name(self):
        procs = [_make_process(name="sshd", cpu=90, runtime=120, remote=5)]
        result = select_candidates(procs, _base_config())
        assert len(result) == 0

    def test_rejects_short_runtime(self):
        procs = [_make_process(cpu=90, runtime=5, remote=5)]
        result = select_candidates(procs, _base_config())
        assert len(result) == 0

    def test_sorted_by_score(self):
        procs = [
            _make_process(pid=1001, cpu=85, runtime=120, remote=1),
            _make_process(pid=1002, cpu=95, runtime=120, remote=10, libssl=True),
        ]
        result = select_candidates(procs, _base_config())
        assert len(result) == 2
        assert result[0]["score"] >= result[1]["score"]


class TestMaxCandidates:
    def test_caps_at_max(self):
        procs = [_make_process(pid=i, cpu=90, runtime=120, remote=5) for i in range(20)]
        result = select_candidates(procs, _base_config())
        assert len(result) <= 10


class TestKernelThreadFilter:
    def test_filters_kernel_threads(self):
        procs = [_make_process(name="kworker/0:1", cpu=90, runtime=120, remote=5, kernel_thread=True)]
        result = select_candidates(procs, _base_config())
        assert len(result) == 0


class TestSystemServiceFilter:
    def test_filters_systemd_journald(self):
        procs = [_make_process(name="systemd-journald", cpu=90, runtime=120, remote=5,
                               system_service_like=True, username="root")]
        result = select_candidates(procs, _base_config())
        assert len(result) == 0

    def test_filters_vmtoolsd(self):
        procs = [_make_process(name="vmtoolsd", cpu=90, runtime=120, remote=5,
                               system_service_like=True, username="root")]
        result = select_candidates(procs, _base_config())
        assert len(result) == 0

    def test_filters_whitelist_path(self):
        procs = [_make_process(name="my-daemon", cpu=90, runtime=120, remote=5,
                               exe_path="/usr/sbin/my-daemon")]
        result = select_candidates(procs, _base_config())
        assert len(result) == 0

    def test_filters_service_user(self):
        procs = [_make_process(name="my-proc", cpu=90, runtime=120, remote=5, username="root")]
        result = select_candidates(procs, _base_config())
        assert len(result) == 0

    def test_keeps_normal_process(self):
        procs = [_make_process(name="my-miner", cpu=90, runtime=120, remote=5,
                               exe_path="/tmp/my-miner", username="nobody")]
        result = select_candidates(procs, _base_config())
        assert len(result) == 1


class TestNameSuspicious:
    def test_xmrig_not_confirmed(self):
        procs = [_make_process(name="xmrig", cpu=90, runtime=120, remote=5,
                               exe_path="/tmp/xmrig", username="nobody")]
        result = select_candidates(procs, _base_config())
        assert len(result) == 1
        assert "name_suspicious" in result[0]["reasons"]
        assert "verdict" not in result[0]
