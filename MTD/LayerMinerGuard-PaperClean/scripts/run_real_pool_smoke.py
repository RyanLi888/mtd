#!/usr/bin/env python3
"""Real pool smoke test runner.

Runs XMRig against a real public pool (plaintext or TLS) for a short
duration to verify probe can capture job/submit markers.

Reads pool config from environment variables — never saves real host/wallet.

MUST run as root (for BPF probes):
    sudo -E bash -lc 'python3 scripts/run_real_pool_smoke.py --mode plaintext ...'

Privacy: never saves raw payload, wallet, job_id, nonce, result, blob.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_env(key: str, required: bool = True) -> str:
    val = os.environ.get(key, "")
    if required and not val:
        print(f"[smoke] ERROR: env {key} not set")
        sys.exit(1)
    return val


def run_smoke(mode: str, session_id: str, duration: int, threads: int, output_dir: str):
    # Must run as root for BPF probes
    if os.geteuid() != 0:
        print("[smoke] ERROR: this script must run as root.")
        print("[smoke] Usage: sudo -E bash -lc 'python3 scripts/run_real_pool_smoke.py ...'")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    # Read config from env
    xmrig_bin = get_env("LMG_XMRIG")
    pool_user = get_env("LMG_POOL_USER")
    pool_pass = os.environ.get("LMG_POOL_PASS", "x")

    if mode == "plaintext":
        pool_host = get_env("LMG_REAL_PLAIN_HOST")
        pool_port = get_env("LMG_REAL_PLAIN_PORT")
        pool_alias = "REAL_POOL_PLAINTEXT"
        url = f"stratum+tcp://{pool_host}:{pool_port}"
    elif mode == "tls":
        pool_host = get_env("LMG_REAL_TLS_HOST")
        pool_port = get_env("LMG_REAL_TLS_PORT")
        pool_alias = "REAL_POOL_TLS"
        url = f"stratum+ssl://{pool_host}:{pool_port}"
        tls_fp = os.environ.get("LMG_TLS_FINGERPRINT", "")
    else:
        print(f"[smoke] ERROR: unknown mode {mode}")
        sys.exit(1)

    print(f"[smoke] Session: {session_id}")
    print(f"[smoke] Mode: {mode}")
    print(f"[smoke] Pool: {pool_alias}")
    print(f"[smoke] Duration: {duration}s")
    print(f"[smoke] Threads: {threads}")

    # Build XMRig command
    xmrig_log = f"/tmp/{session_id}_xmrig.log"
    xmrig_cmd = [
        xmrig_bin, f"--url={url}",
        "--user", pool_user, "--pass", pool_pass,
        f"--threads={threads}",
        "--donate-level=0", "--no-huge-pages",
        f"--log-file={xmrig_log}",
    ]
    if mode == "tls" and tls_fp:
        xmrig_cmd.append(f"--tls-fingerprint={tls_fp}")
    elif mode == "tls":
        xmrig_cmd.append("--tls")

    # Start XMRig
    print(f"[smoke] Starting XMRig...")
    xmrig_proc = subprocess.Popen(
        xmrig_cmd,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(15)  # Wait for XMRig to initialize

    # Check if XMRig is still running
    if xmrig_proc.poll() is not None:
        print(f"[smoke] ERROR: XMRig exited early with code {xmrig_proc.returncode}")
        if os.path.exists(xmrig_log):
            with open(xmrig_log) as f:
                for line in f:
                    if "error" in line.lower() or "fail" in line.lower():
                        print(f"  {line.strip()}")
        return {"session_id": session_id, "smoke_status": "fail", "notes": "xmrig_exited_early"}

    pid = xmrig_proc.pid
    print(f"[smoke] XMRig PID: {pid}")

    # Start probe (we are root, run directly — no sudo needed)
    probe_script = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                 "probes", "tls_openssl_probe.py" if mode == "tls" else "plaintext_stratum_probe.py")
    probe_output = f"/tmp/{session_id}_probe.json"

    print(f"[smoke] Starting probe (as root)...")
    probe_proc = subprocess.Popen(
        [sys.executable, probe_script,
         "--pid", str(pid), "--duration", str(duration + 30),
         "--output", probe_output],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

    # Wait for duration
    print(f"[smoke] Waiting {duration}s...")
    time.sleep(duration)

    # Check hashrate from log
    hashrate_observed = False
    if os.path.exists(xmrig_log):
        with open(xmrig_log) as f:
            content = f.read()
        if re.search(r'speed\s+\S+\s+(\d+\.\d+)', content):
            hr = float(re.search(r'speed\s+\S+\s+(\d+\.\d+)', content).group(1))
            hashrate_observed = hr > 0
            print(f"[smoke] Hashrate: {hr}")

    # Stop XMRig
    print(f"[smoke] Stopping XMRig...")
    xmrig_proc.terminate()
    try:
        xmrig_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        xmrig_proc.kill()

    # Wait for probe to finish
    try:
        probe_out, _ = probe_proc.communicate(timeout=30)
        if probe_out:
            print(f"[smoke] Probe: {probe_out.decode()[:200]}")
    except subprocess.TimeoutExpired:
        probe_proc.kill()

    # Read probe results
    probe_data = {}
    if os.path.exists(probe_output):
        try:
            with open(probe_output) as f:
                probe_data = json.load(f)
        except Exception as e:
            print(f"[smoke] Error reading probe output: {e}")

    job = probe_data.get("job_marker_count", 0)
    submit = probe_data.get("submit_marker_count", 0)
    assoc = probe_data.get("associated_submit_count", 0)

    # Determine status
    if job > 0 and submit > 0 and assoc > 0:
        smoke_status = "pass"
        notes = "full_evidence_chain_observed"
    elif job > 0 and submit > 0:
        smoke_status = "pass"
        notes = "job_and_submit_observed"
    elif job > 0:
        smoke_status = "partial"
        notes = "job_observed_but_no_submit"
    elif hashrate_observed:
        smoke_status = "partial"
        notes = "hashrate_observed_but_no_protocol_markers"
    else:
        smoke_status = "fail"
        notes = "no_markers_no_hashrate"

    print(f"[smoke] Results: job={job} submit={submit} assoc={assoc}")
    print(f"[smoke] Status: {smoke_status} ({notes})")

    # Residual check
    residual = []
    for proc in [xmrig_proc, probe_proc]:
        if proc and proc.poll() is None:
            residual.append(proc.pid)

    if residual:
        print(f"[smoke] WARNING: residual PIDs: {residual}")
        for pid in residual:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    # Build summary (no real host/wallet/raw payload/job_id/nonce/result/blob)
    summary = {
        "session_id": session_id,
        "pool_alias": pool_alias,
        "visibility_mode": mode,
        "duration_sec": duration,
        "xmrig_version": "6.26.0",
        "threads": threads,
        "job_marker_count": job,
        "submit_marker_count": submit,
        "associated_submit_count": assoc,
        "hashrate_observed": hashrate_observed,
        "raw_payload_saved": False,
        "wallet_saved": False,
        "job_id_saved": False,
        "nonce_saved": False,
        "result_saved": False,
        "blob_saved": False,
        "residual_processes": residual,
        "smoke_status": smoke_status,
        "notes": notes,
    }

    # Save summary
    summary_path = os.path.join(output_dir, f"{session_id}_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"[smoke] Summary: {summary_path}")

    # Cleanup XMRig log (may contain real pool host/wallet)
    try:
        os.remove(xmrig_log)
    except OSError:
        pass

    return summary


def main():
    parser = argparse.ArgumentParser(description="Real pool smoke test")
    parser.add_argument("--mode", choices=["plaintext", "tls"], required=True)
    parser.add_argument("--session-id", type=str, required=True)
    parser.add_argument("--duration", type=int, default=300)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--output-dir", type=str, default="experiments/exp0_real_pool_smoke")
    args = parser.parse_args()

    summary = run_smoke(args.mode, args.session_id, args.duration, args.threads, args.output_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
