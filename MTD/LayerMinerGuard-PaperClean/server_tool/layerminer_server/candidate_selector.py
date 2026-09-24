"""Candidate selector for LayerMinerGuard server tool.

Selects suspicious process candidates based on configurable rules.
Never confirms mining — only marks candidates for observation.
"""


def _compute_observation_eligibility(reasons: list[str]) -> tuple[bool, int, str]:
    """Determine if a candidate is eligible for probe observation.

    Strong signal rules:
      - name_suspicious + network_activity + runtime_ok
      - high_cpu + network_activity + runtime_ok
      - has_libssl + high_cpu + network_activity + runtime_ok

    Weak signal (not eligible):
      - network_activity + runtime_ok only (no high_cpu, no name_suspicious)

    Returns:
        (eligible, priority, block_reason)
    """
    has_high_cpu = "high_cpu" in reasons
    has_network = "network_activity" in reasons
    has_runtime = "runtime_ok" in reasons
    has_name_suspicious = "name_suspicious" in reasons
    has_libssl = "has_libssl" in reasons

    if not (has_runtime and has_network):
        return False, 0, "insufficient_signal"

    eligible = has_name_suspicious or has_high_cpu or (has_libssl and has_high_cpu)

    if not eligible:
        return False, 0, "weak_network_only_signal"

    # Compute priority (higher = more suspicious)
    priority = 0
    if has_name_suspicious and has_high_cpu:
        priority = 100
    elif has_name_suspicious:
        priority = 80
    elif has_libssl and has_high_cpu:
        priority = 70
    elif has_high_cpu:
        priority = 50
    else:
        priority = 30  # shouldn't reach here if eligible, but safety

    return True, priority, ""


def select_candidates(processes: list[dict], config: dict) -> list[dict]:
    """Select suspicious process candidates from scanned processes.

    Args:
        processes: List of process dicts from process_scanner.
        config: Configuration dict with candidate selection rules.

    Returns:
        List of candidate dicts with score, reasons, observation_eligible,
        observation_priority, observation_block_reason. Sorted by
        observation_eligible (True first), then priority desc, then score desc.
    """
    cand_cfg = config.get("candidate", {})
    min_cpu = cand_cfg.get("min_cpu_percent", 80)
    min_runtime = cand_cfg.get("min_runtime_sec", 60)
    require_net = cand_cfg.get("require_network", True)
    whitelist_names = set(cand_cfg.get("whitelist_names", []))
    whitelist_paths = cand_cfg.get("whitelist_paths", [])
    max_candidates = cand_cfg.get("max_candidates_per_scan", 10)
    ignore_kthreads = cand_cfg.get("ignore_kernel_threads", True)
    ignore_sys_svc = cand_cfg.get("ignore_system_services", True)
    ignore_svc_users = set(cand_cfg.get("ignore_service_users", []))

    candidates = []

    for proc in processes:
        reasons = []
        name = proc.get("name", "")
        exe_path = proc.get("exe_path", "")
        username = proc.get("username", "")
        cpu_pct = proc.get("cpu_percent", 0)
        runtime = proc.get("runtime_sec", 0)
        remote = proc.get("remote_count", 0)

        # Skip kernel threads
        if ignore_kthreads and proc.get("kernel_thread", False):
            continue

        # Skip whitelisted names
        if name in whitelist_names:
            continue

        # Skip whitelisted paths
        if any(exe_path.startswith(p) for p in whitelist_paths):
            continue

        # Skip system services
        if ignore_sys_svc and proc.get("system_service_like", False):
            continue

        # Skip service users
        if username in ignore_svc_users:
            continue

        reasons.append("not_whitelisted")

        # Runtime check
        if runtime >= min_runtime:
            reasons.append("runtime_ok")
        else:
            continue

        # Network check
        if require_net and remote > 0:
            reasons.append("network_activity")
        elif not require_net:
            reasons.append("network_not_required")
        else:
            continue

        # CPU check
        if cpu_pct >= min_cpu:
            reasons.append("high_cpu")

        # Signal check
        has_signal = "high_cpu" in reasons or "network_activity" in reasons
        if not has_signal:
            continue

        # libssl check
        if proc.get("has_libssl", False):
            reasons.append("has_libssl")

        # Name-based suspicion
        if name.lower() in ("xmrig", "xmr-stak", "ccminer", "cgminer", "bfgminer"):
            reasons.append("name_suspicious")

        # Score
        score = 0.0
        if "high_cpu" in reasons:
            score += 0.4
        if "network_activity" in reasons:
            score += 0.3
        if "runtime_ok" in reasons:
            score += 0.2
        if "has_libssl" in reasons:
            score += 0.1
        if "name_suspicious" in reasons:
            score += 0.15

        # Observation eligibility
        eligible, priority, block_reason = _compute_observation_eligibility(reasons)

        candidates.append({
            "pid": proc.get("pid"),
            "name": name,
            "score": round(score, 2),
            "reasons": sorted(reasons),
            "process": proc,
            "observation_eligible": eligible,
            "observation_priority": priority,
            "observation_block_reason": block_reason,
        })

    # Sort: eligible first, then priority desc, then score desc
    candidates.sort(
        key=lambda c: (c["observation_eligible"], c["observation_priority"], c["score"]),
        reverse=True,
    )

    return candidates[:max_candidates]
