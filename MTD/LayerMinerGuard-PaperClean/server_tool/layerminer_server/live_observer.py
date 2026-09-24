"""Live observer for LayerMinerGuard server tool.

Runs short-window probes against confirmed candidate processes.
Never saves raw payload, wallet, job_id, nonce, result, or blob.
"""

import json
import os
import subprocess
import sys
import time
import tempfile


def _get_create_time(pid: int) -> float:
    """Get process creation time. Returns 0.0 on failure."""
    try:
        import psutil
        return psutil.Process(pid).create_time()
    except Exception:
        pass
    try:
        with open(f"/proc/{pid}/stat") as f:
            stat = f.read().split()
        starttime_ticks = int(stat[21])
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
        boot_time = time.time() - uptime
        hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        return boot_time + starttime_ticks / hz
    except (OSError, ValueError, IndexError):
        return 0.0


def _get_exe_hash(pid: int) -> str:
    """Get hash of process executable. Returns empty string on failure."""
    import hashlib
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
        h = hashlib.sha256()
        with open(exe_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return "sha256:" + h.hexdigest()[:16]
    except (OSError, PermissionError):
        return ""


def validate_candidate_process(candidate: dict) -> tuple[bool, dict]:
    """Validate that a candidate PID still matches its expected identity.

    Args:
        candidate: Candidate dict with pid and process info.

    Returns:
        Tuple of (is_valid, validation_dict).
    """
    from .process_scanner import build_process_identity_key

    pid = candidate.get("pid", 0)
    proc = candidate.get("process", {})
    expected_key = proc.get("identity_key", "")
    expected_create_time = proc.get("create_time", 0.0)
    expected_exe_hash = proc.get("exe_hash", "")

    # Check PID exists
    if not os.path.exists(f"/proc/{pid}"):
        return False, {
            "valid": False,
            "reason": "pid_not_found",
            "pid": pid,
            "expected_identity_key": expected_key,
            "current_identity_key": "",
        }

    # Get current process identity
    current_create_time = _get_create_time(pid)
    current_exe_hash = expected_exe_hash  # assume same unless we can re-check

    # If we have an expected create_time, verify it matches
    if expected_create_time > 0 and current_create_time > 0:
        # Allow 1 second tolerance for floating point
        if abs(current_create_time - expected_create_time) > 1.0:
            current_key = build_process_identity_key(
                pid, current_create_time, current_exe_hash, candidate.get("name", ""))
            return False, {
                "valid": False,
                "reason": "pid_identity_mismatch",
                "pid": pid,
                "expected_identity_key": expected_key,
                "current_identity_key": current_key,
            }

    # If we have an expected exe_hash, re-verify
    if expected_exe_hash:
        fresh_hash = _get_exe_hash(pid)
        if fresh_hash and fresh_hash != expected_exe_hash:
            current_key = build_process_identity_key(
                pid, current_create_time, fresh_hash, candidate.get("name", ""))
            return False, {
                "valid": False,
                "reason": "exe_hash_mismatch",
                "pid": pid,
                "expected_identity_key": expected_key,
                "current_identity_key": current_key,
            }

    return True, {"valid": True, "pid": pid}


def _get_cpu_avg(pid: int, duration: int) -> float:
    """Sample CPU usage for a process over duration seconds."""
    try:
        import psutil
        proc = psutil.Process(pid)
        samples = []
        for _ in range(min(duration, 10)):
            try:
                samples.append(proc.cpu_percent(interval=1.0))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
        return round(sum(samples) / len(samples), 1) if samples else 0.0
    except (ImportError, Exception):
        return 0.0


def _run_probe(probe_script: str, pid: int, duration: int, output_path: str,
               timeout: int = 120, early_confirm_cfg: dict = None) -> dict:
    """Run a probe script and return its summary.

    Args:
        probe_script: Path to probe Python script.
        pid: Target process PID.
        duration: Probe duration in seconds.
        output_path: Path for probe JSON output.
        timeout: Max seconds to wait for probe.
        early_confirm_cfg: Early confirm config dict or None.

    Returns:
        Probe summary dict.
    """
    result = {
        "enabled": True,
        "job_marker_count": 0,
        "submit_marker_count": 0,
        "associated_submit_count": 0,
        "raw_payload_saved": False,
        "probe_exit_code": -1,
    }

    try:
        cmd = [sys.executable, probe_script,
               "--pid", str(pid), "--duration", str(duration),
               "--output", output_path]
        if early_confirm_cfg and early_confirm_cfg.get("enabled", False):
            cmd += [
                "--early-confirm",
                "--early-check-interval", str(early_confirm_cfg.get("check_interval_sec", 5)),
                "--early-min-job", str(early_confirm_cfg.get("min_job_markers", 1)),
                "--early-min-submit", str(early_confirm_cfg.get("min_submit_markers", 1)),
                "--early-min-assoc", str(early_confirm_cfg.get("min_associated_submits", 1)),
            ]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        try:
            stdout, _ = proc.communicate(timeout=timeout)
            result["probe_exit_code"] = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            result["probe_exit_code"] = -2
            return result

        # Read probe output JSON
        if os.path.exists(output_path):
            try:
                with open(output_path) as f:
                    probe_data = json.load(f)
                result["job_marker_count"] = probe_data.get("job_marker_count", 0)
                result["submit_marker_count"] = probe_data.get("submit_marker_count", 0)
                result["associated_submit_count"] = probe_data.get("associated_submit_count", 0)
                result["early_confirmed"] = probe_data.get("early_confirmed", False)
                result["actual_observe_duration_sec"] = probe_data.get("actual_observe_duration_sec", 0.0)
            except (json.JSONDecodeError, OSError):
                pass

    except Exception as e:
        result["probe_exit_code"] = -3

    return result


def observe_candidate_live(candidate: dict, config: dict) -> dict:
    """Run live observation on a confirmed candidate.

    Args:
        candidate: Confirmed candidate dict with pid, name, etc.
        config: Configuration dict.

    Returns:
        Observation summary dict.
    """
    obs_cfg = config.get("observer", {})
    agent_cfg = config.get("agent", {})
    probe_duration = obs_cfg.get("plaintext_probe_duration_sec", 90)
    probe_timeout = obs_cfg.get("probe_timeout_sec", 120)
    enable_plain = obs_cfg.get("enable_plaintext_probe", True)
    enable_tls = obs_cfg.get("enable_tls_probe", True)
    cpu_threshold = config.get("verdict", {}).get("compute_cpu_threshold_percent", 30)

    pid = candidate.get("pid", 0)
    proc = candidate.get("process", {})
    has_libssl = proc.get("has_libssl", False)

    # Validate PID identity BEFORE launching any probe
    is_valid, validation = validate_candidate_process(candidate)
    if not is_valid:
        return {
            "pid": pid,
            "process_name": candidate.get("name", ""),
            "observe_skipped": True,
            "skip_reason": validation.get("reason", "unknown"),
            "identity_validation": validation,
            "observe_duration_sec": probe_duration,
            "cpu_avg_percent": 0.0,
            "compute_evidence_present": False,
            "has_libssl": False,
            "plaintext": {"enabled": False, "job_marker_count": 0, "submit_marker_count": 0,
                          "associated_submit_count": 0, "raw_payload_saved": False, "probe_exit_code": -1},
            "tls": {"enabled": False, "job_marker_count": 0, "submit_marker_count": 0,
                    "associated_submit_count": 0, "raw_payload_saved": False, "probe_exit_code": -1},
            "privacy": {"raw_payload_saved": False, "wallet_saved": False, "job_id_saved": False,
                        "nonce_saved": False, "result_saved": False, "blob_saved": False},
            "error": "pid_not_found",
        }

    # Sample CPU
    cpu_avg = _get_cpu_avg(pid, min(probe_duration, 15))
    compute_present = cpu_avg >= cpu_threshold

    # Temp dir for probe outputs
    tmpdir = tempfile.mkdtemp(prefix="lmg_obs_")
    plain_output = os.path.join(tmpdir, "plaintext_probe.json")
    tls_output = os.path.join(tmpdir, "tls_probe.json")

    # Project root for probe scripts
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    plain_script = os.path.join(project_root, "probes", "plaintext_stratum_probe.py")
    tls_script = os.path.join(project_root, "probes", "tls_openssl_probe.py")

    # Early confirm config
    early_cfg = obs_cfg.get("early_confirm", {})

    # Run plaintext probe
    plain_result = {"enabled": False, "job_marker_count": 0, "submit_marker_count": 0,
                    "associated_submit_count": 0, "raw_payload_saved": False, "probe_exit_code": 0}
    if enable_plain:
        plain_result = _run_probe(plain_script, pid, probe_duration, plain_output, probe_timeout, early_cfg)

    # Run TLS probe if libssl detected AND plaintext didn't already early-confirm
    tls_result = {"enabled": False, "job_marker_count": 0, "submit_marker_count": 0,
                  "associated_submit_count": 0, "raw_payload_saved": False, "probe_exit_code": 0}
    plain_early = plain_result.get("early_confirmed", False)
    if enable_tls and has_libssl and not plain_early:
        tls_result = _run_probe(tls_script, pid, probe_duration, tls_output, probe_timeout, early_cfg)

    # Cleanup temp files
    for f in [plain_output, tls_output]:
        try:
            os.remove(f)
        except OSError:
            pass
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass

    # Determine overall early_confirmed status
    overall_early = plain_result.get("early_confirmed", False) or tls_result.get("early_confirmed", False)
    actual_dur = plain_result.get("actual_observe_duration_sec", 0.0)
    if tls_result.get("early_confirmed", False):
        actual_dur = max(actual_dur, tls_result.get("actual_observe_duration_sec", 0.0))
    if actual_dur == 0.0:
        actual_dur = float(probe_duration)

    return {
        "pid": pid,
        "process_name": candidate.get("name", ""),
        "observe_duration_sec": probe_duration,
        "actual_observe_duration_sec": round(actual_dur, 1),
        "cpu_avg_percent": cpu_avg,
        "compute_evidence_present": compute_present,
        "has_libssl": has_libssl,
        "early_confirmed": overall_early,
        "plaintext": plain_result,
        "tls": tls_result,
        "privacy": {
            "raw_payload_saved": False,
            "wallet_saved": False,
            "job_id_saved": False,
            "nonce_saved": False,
            "result_saved": False,
            "blob_saved": False,
        },
    }
