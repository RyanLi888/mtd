"""Tests for process_scanner module."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.process_scanner import (
    scan_processes,
    _sanitize_cmdline,
    _has_libssl,
    _is_kernel_thread,
    _is_system_service_like,
)


class TestSanitizeCmdline:
    def test_empty_cmdline(self):
        assert _sanitize_cmdline("") == ""

    def test_normal_cmdline(self):
        result = _sanitize_cmdline("/usr/bin/python3 script.py --port 8080")
        assert "python3" in result
        assert "REDACTED" not in result

    def test_redacts_user_param(self):
        result = _sanitize_cmdline("xmrig --user WALLET_ADDRESS --pass x")
        assert "WALLET_ADDRESS" not in result
        assert "REDACTED" in result

    def test_redacts_password_param(self):
        result = _sanitize_cmdline("app --password mysecret123")
        assert "mysecret123" not in result
        assert "REDACTED" in result

    def test_truncates_long_cmdline(self):
        long_cmd = "app " + "x" * 200
        result = _sanitize_cmdline(long_cmd)
        assert len(result) <= 124  # 120 + "..."


class TestScanProcesses:
    def test_returns_list(self):
        config = {"candidate": {"whitelist_names": []}}
        result = scan_processes(config)
        assert isinstance(result, list)

    def test_process_has_required_fields(self):
        config = {"candidate": {"whitelist_names": []}}
        result = scan_processes(config)
        if result:
            proc = result[0]
            required = [
                "pid", "ppid", "name", "exe_path", "exe_hash",
                "username", "is_root_process", "system_service_like",
                "cpu_percent", "memory_rss", "runtime_sec",
                "connection_count", "remote_count", "has_libssl",
                "kernel_thread", "cmdline_hash", "cmdline_preview_sanitized",
            ]
            for field in required:
                assert field in proc, f"Missing field: {field}"

    def test_no_raw_cmdline_saved(self):
        config = {"candidate": {"whitelist_names": []}}
        result = scan_processes(config)
        for proc in result:
            assert "cmdline" not in proc or proc.get("cmdline") is None

    def test_username_is_string(self):
        config = {"candidate": {"whitelist_names": []}}
        result = scan_processes(config)
        for proc in result:
            assert isinstance(proc.get("username", ""), str)

    def test_system_service_like_is_bool(self):
        config = {"candidate": {"whitelist_names": []}}
        result = scan_processes(config)
        for proc in result:
            assert isinstance(proc.get("system_service_like", False), bool)


class TestHasLibssl:
    def test_returns_bool(self):
        result = _has_libssl(1)
        assert isinstance(result, bool)


class TestIsKernelThread:
    def test_kworker(self):
        assert _is_kernel_thread("kworker/0:1") is True

    def test_kthreadd(self):
        assert _is_kernel_thread("kthreadd") is True

    def test_rcu_sched(self):
        assert _is_kernel_thread("rcu_sched") is True

    def test_migration(self):
        assert _is_kernel_thread("migration/0") is True

    def test_normal_process(self):
        assert _is_kernel_thread("python3") is False

    def test_empty_name(self):
        assert _is_kernel_thread("") is False

    def test_process_has_kernel_thread_field(self):
        config = {"candidate": {"whitelist_names": []}}
        result = scan_processes(config)
        if result:
            assert "kernel_thread" in result[0]


class TestIsSystemServiceLike:
    def test_systemd_journald(self):
        assert _is_system_service_like("systemd-journald", "/usr/lib/systemd/systemd-journald", "root") is True

    def test_vmtoolsd(self):
        assert _is_system_service_like("vmtoolsd", "/usr/bin/vmtoolsd", "root") is True

    def test_acpid(self):
        assert _is_system_service_like("acpid", "/usr/sbin/acpid", "root") is True

    def test_systemd_path(self):
        assert _is_system_service_like("custom-svc", "/usr/lib/systemd/custom-svc", "root") is True

    def test_usr_sbin(self):
        assert _is_system_service_like("mydaemon", "/usr/sbin/mydaemon", "root") is True

    def test_normal_process(self):
        assert _is_system_service_like("python3", "/usr/bin/python3", "axkk") is False
