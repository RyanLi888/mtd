#!/usr/bin/env python3
"""Run a single plaintext positive session.

Local fake plaintext pool + XMRig (plaintext mode).
Verifies job/submit markers, compute, closure, association.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_session(session_id: str, xmrig_bin: str, duration: int, port: int, output_dir: str):
    """Run one plaintext positive session."""
    os.makedirs(output_dir, exist_ok=True)

    pool_proc = None
    xmrig_proc = None
    residual_pids = []

    try:
        # 1. Start fake plaintext pool
        pool_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), "workloads", "fake_plaintext_pool.py")
        pool_proc = subprocess.Popen(
            [sys.executable, pool_script, "--port", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(3)
        print(f"[runner] Pool started PID={pool_proc.pid}")

        # 2. Start XMRig (plaintext mode)
        xmrig_proc = subprocess.Popen(
            [xmrig_bin, f"--url=127.0.0.1:{port}", "--user=test", "--pass=x",
             "--threads=2", "--donate-level=0", "--no-huge-pages",
             f"--log-file={output_dir}/{session_id}_xmrig.log"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(5)
        print(f"[runner] XMRig started PID={xmrig_proc.pid}")

        # 3. Start plaintext probe (needs sudo for BPF)
        probe_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), "probes", "plaintext_stratum_probe.py")
        probe_output = f"{output_dir}/{session_id}_probe.json"
        probe_proc = subprocess.Popen(
            ["sudo", sys.executable, probe_script, "--pid", str(xmrig_proc.pid),
             "--duration", str(duration + 30), "--output", probe_output],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"[runner] Probe started PID={probe_proc.pid}")

        # 4. Wait
        time.sleep(duration)

        # 5. Stop XMRig
        xmrig_proc.terminate()
        try:
            xmrig_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            xmrig_proc.kill()
        print(f"[runner] XMRig stopped")

        # 6. Wait for probe to finish
        try:
            probe_proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            probe_proc.kill()
        print(f"[runner] Probe stopped")

        # 7. Read probe results
        probe_data = {}
        if os.path.exists(probe_output):
            with open(probe_output) as f:
                probe_data = json.load(f)

        # 8. Read XMRig log for hashrate
        xmrig_log = f"{output_dir}/{session_id}_xmrig.log"
        hashrate = 0
        if os.path.exists(xmrig_log):
            import re
            with open(xmrig_log) as f:
                content = f.read()
            match = re.search(r'speed\s+\S+\s+(\d+\.\d+)', content)
            if match:
                hashrate = float(match.group(1))

        # 9. Build result
        result = {
            "session_id": session_id,
            "visibility_mode": "plaintext_stratum",
            "duration_sec": duration,
            "hashrate": hashrate,
            "job_marker_count": probe_data.get("job_marker_count", 0),
            "submit_marker_count": probe_data.get("submit_marker_count", 0),
            "associated_submit_count": probe_data.get("associated_submit_count", 0),
            "raw_payload_saved": False,
            "residual_pids": [],
        }

        # Save
        result_path = f"{output_dir}/{session_id}.json"
        with open(result_path, 'w') as f:
            json.dump(result, f, indent=2)

        print(f"[runner] {session_id}: job={result['job_marker_count']} submit={result['submit_marker_count']} assoc={result['associated_submit_count']} hr={hashrate}")
        return result

    except Exception as e:
        print(f"[runner] ERROR: {e}")
        return {"session_id": session_id, "error": str(e)}

    finally:
        # Cleanup
        for proc in [pool_proc, xmrig_proc, probe_proc]:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except:
                    proc.kill()

        # Residual check
        residual_pids = []
        for proc in [pool_proc, xmrig_proc, probe_proc]:
            if proc and proc.poll() is None:
                residual_pids.append(proc.pid)

        if residual_pids:
            print(f"[runner] WARNING: residual PIDs: {residual_pids}")
        else:
            print(f"[runner] Cleanup OK, no residual processes")


def main():
    parser = argparse.ArgumentParser(description="Run plaintext positive session")
    parser.add_argument("--session-id", type=str, default="plaintext_smoke_001")
    parser.add_argument("--xmrig", type=str, default="/home/axkk/tools/xmrig/xmrig-6.26.0/xmrig")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--port", type=int, default=13000)
    parser.add_argument("--output-dir", type=str, default="experiments/exp0_smoke")
    args = parser.parse_args()

    result = run_session(args.session_id, args.xmrig, args.duration, args.port, args.output_dir)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
