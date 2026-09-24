#!/usr/bin/env python3
"""Single session runner.

Runs one mining detection session with proper lifecycle management:
1. Start fake pool
2. Launch workload (suspended)
3. Start probes
4. Resume workload
5. Wait duration
6. Stop workload
7. Stop probes
8. Compute closure
9. Generate session summary

Supports both plaintext and TLS modes.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layerminer.schema import (
    SessionSummary, MarkerSummary, Evidence, PrivacyRecord, Verdict,
    VISIBILITY_PLAINTEXT, VISIBILITY_TLS, VISIBILITY_UNAVAILABLE,
)
from layerminer.evidence_chain import reconstruct_evidence, compute_session_closed
from layerminer.detector import detect_full


class SessionRunner:
    """Runs a single mining detection session."""

    def __init__(self, session_id: str, config: dict):
        self.session_id = session_id
        self.config = config
        self.duration = config.get('duration_sec', 300)
        self.visibility = config.get('visibility', 'plaintext')
        self.target_program = config.get('target_program', 'xmrig')
        self.pool_port = config.get('pool_port', 13000)

        # Process tracking
        self.pool_pid = None
        self.workload_pid = None
        self.probe_pids = []

        # Results
        self.marker_summary = None
        self.compute_present = False
        self.behavioral_closure = False
        self.session_closed = False
        self.exit_code = 0
        self.residual_pids = []

    def cleanup(self):
        """Kill all tracked processes."""
        pids = [self.pool_pid, self.workload_pid] + self.probe_pids
        pids = [p for p in pids if p is not None]

        # SIGTERM
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        time.sleep(5)

        # SIGKILL
        for pid in pids:
            try:
                if os.path.exists(f'/proc/{pid}'):
                    os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        time.sleep(2)

        # Residual check
        self.residual_pids = []
        for pid in pids:
            try:
                os.kill(pid, 0)  # Check if alive
                self.residual_pids.append(pid)
            except (ProcessLookupError, PermissionError):
                pass

        if self.residual_pids:
            print(f"[runner] WARNING: {len(self.residual_pids)} residual PIDs: {self.residual_pids}")

    def run(self) -> SessionSummary:
        """Run the session and return summary."""
        start_ts = time.time()

        try:
            # 1. Start pool
            self._start_pool()

            # 2. Start workload
            self._start_workload()

            # 3. Start probes
            self._start_probes()

            # 4. Wait
            time.sleep(self.duration)

            # 5. Extract results
            self._extract_results()

        except Exception as e:
            print(f"[runner] ERROR: {e}")
            self.exit_code = 1

        finally:
            # 6. Cleanup
            self.cleanup()

        # 7. Build summary
        duration_sec = int(time.time() - start_ts)
        marker = self.marker_summary or MarkerSummary(visibility_mode=self.visibility)
        evidence = reconstruct_evidence(
            marker=marker,
            compute_present=self.compute_present,
            behavioral_closure=self.behavioral_closure,
            session_closed=self.session_closed,
        )
        verdict = detect_full(evidence)

        summary = SessionSummary(
            session_id=self.session_id,
            experiment=self.config.get('experiment', ''),
            scenario=self.config.get('scenario', ''),
            duration_sec=duration_sec,
            target_program=self.target_program,
            target_version=self.config.get('target_version', ''),
            target_linkage=self.config.get('target_linkage', 'dynamic'),
            visibility_mode=marker.visibility_mode,
            probe_backend=self.config.get('probe_backend', ''),
            evidence=evidence,
            privacy=PrivacyRecord(),
            verdict=verdict,
            runner_exit_code=self.exit_code,
            runner_residual_pids=self.residual_pids,
            producer_commit=self._get_git_commit(),
            timestamp=time.time(),
        )

        return summary

    def _start_pool(self):
        """Start fake pool."""
        pool_script = self.config.get('pool_script', '')
        if not pool_script:
            return

        cmd = [
            sys.executable, pool_script,
            '--port', str(self.pool_port),
        ]
        if self.config.get('pool_cert'):
            cmd.extend(['--cert', self.config['pool_cert']])
        if self.config.get('pool_key'):
            cmd.extend(['--key', self.config['pool_key']])

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pool_pid = proc.pid
        time.sleep(3)

    def _start_workload(self):
        """Start mining workload."""
        workload_cmd = self.config.get('workload_cmd', '')
        if not workload_cmd:
            return

        proc = subprocess.Popen(
            workload_cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.workload_pid = proc.pid
        time.sleep(5)

    def _start_probes(self):
        """Start probes based on visibility mode."""
        # Network observer
        net_script = self.config.get('net_observer_script', '')
        if net_script and self.workload_pid:
            proc = subprocess.Popen([
                sys.executable, net_script,
                str(self.workload_pid), str(self.duration + 30),
                self.config.get('net_output', '/dev/null'),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.probe_pids.append(proc.pid)

        # Semantic probe
        probe_script = self.config.get('probe_script', '')
        if probe_script and self.workload_pid:
            cmd = [sys.executable, probe_script]
            if self.visibility == 'tls':
                cmd.extend(['--pid', str(self.workload_pid)])
            else:
                cmd.extend(['--tgid', str(self.workload_pid)])
            cmd.extend(['--duration', str(self.duration + 30)])
            if self.config.get('probe_output'):
                cmd.extend(['--output', self.config['probe_output']])

            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.probe_pids.append(proc.pid)

        # CPU telemetry
        telem_script = self.config.get('telemetry_script', '')
        if telem_script and self.workload_pid:
            proc = subprocess.Popen([
                sys.executable, telem_script,
                str(self.workload_pid), str(self.duration),
                self.config.get('telemetry_output', '/dev/null'),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.probe_pids.append(proc.pid)

    def _extract_results(self):
        """Extract results from probe outputs."""
        # Load probe summary
        probe_output = self.config.get('probe_output', '')
        if probe_output and os.path.exists(probe_output):
            with open(probe_output) as f:
                data = json.load(f)
            self.marker_summary = MarkerSummary(
                visibility_mode=data.get('visibility_mode', self.visibility),
                job_marker_count=data.get('job_marker_count', 0),
                submit_marker_count=data.get('submit_marker_count', 0),
                associated_submit_count=data.get('associated_submit_count', 0),
                raw_payload_saved=False,
            )

        # Load telemetry
        telem_output = self.config.get('telemetry_output', '')
        if telem_output and os.path.exists(telem_output):
            with open(telem_output) as f:
                telem = json.load(f)
            self.compute_present = telem.get('cpu_avg_percent', 0) > 30

    def _get_git_commit(self) -> str:
        """Get current git commit hash."""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"


def main():
    parser = argparse.ArgumentParser(description="Run single mining detection session")
    parser.add_argument("--config", type=str, required=True, help="Config YAML path")
    parser.add_argument("--session-id", type=str, default="", help="Session ID")
    parser.add_argument("--output", type=str, default="", help="Output JSON path")
    args = parser.parse_args()

    import yaml
    with open(args.config) as f:
        config = yaml.safe_load(f)

    session_id = args.session_id or f"session_{int(time.time())}"
    runner = SessionRunner(session_id, config)
    summary = runner.run()

    if args.output:
        summary.to_json(args.output)

    print(f"[runner] {session_id}: {summary.verdict}")


if __name__ == "__main__":
    main()
