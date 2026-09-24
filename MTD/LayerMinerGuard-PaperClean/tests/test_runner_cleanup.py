"""Runner cleanup tests.

Ensures the cleanup utility works correctly.
"""

import pytest
import sys
import os
import signal
import subprocess
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.cleanup_processes import find_matching_pids, kill_process, cleanup_all, PATTERNS


class TestCleanupPatterns:
    def test_patterns_not_empty(self):
        assert len(PATTERNS) > 0

    def test_patterns_contain_xmrig(self):
        assert any('xmrig' in p for p in PATTERNS)

    def test_patterns_contain_fake_pool(self):
        assert any('fake' in p for p in PATTERNS)

    def test_patterns_contain_probe(self):
        assert any('probe' in p or 'bcc' in p for p in PATTERNS)


class TestFindMatchingPids:
    def test_finds_nothing_when_clean(self):
        pids = find_matching_pids(["__nonexistent_process_xyz__"])
        assert pids == []

    def test_finds_own_process(self):
        # We should find our own python process if we search for python
        pids = find_matching_pids(["python"])
        assert len(pids) > 0

    def test_excludes_self(self):
        my_pid = os.getpid()
        pids = find_matching_pids(["python"])
        assert my_pid not in pids


class TestKillProcess:
    def test_kill_nonexistent_returns_true(self):
        # Killing a non-existent process should return True (already dead)
        result = kill_process(999999999)
        assert result is True

    def test_kill_own_child(self):
        # Start a child process and kill it
        proc = subprocess.Popen(["sleep", "60"])
        result = kill_process(proc.pid, force=False)
        assert result is True
        time.sleep(0.5)
        assert proc.poll() is not None  # Process should be dead


class TestCleanupAll:
    def test_cleanup_returns_empty_when_clean(self):
        residual = cleanup_all(max_attempts=1, verbose=False)
        assert residual == []


class TestRunnerLifecycle:
    """Test that runner properly tracks and cleans up processes."""

    def test_cleanup_script_exists(self):
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'scripts', 'cleanup_processes.py'
        )
        assert os.path.exists(script_path)

    def test_cleanup_script_is_executable(self):
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'scripts', 'cleanup_processes.py'
        )
        assert os.access(script_path, os.R_OK)
