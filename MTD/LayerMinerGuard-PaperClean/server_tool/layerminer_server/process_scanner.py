"""Process scanner for LayerMinerGuard server tool.

Scans system processes and returns sanitized process summaries.
Never saves raw cmdline — only hashed and sanitized previews.
"""

import hashlib
import os
import re
import time


def build_process_identity_key(pid: int, create_time: float, exe_hash: str, name: str = "") -> str:
    """Build a unique identity key for a process instance.

    Uses pid:create_time:stable where stable is exe_hash or name.

    Args:
        pid: Process PID.
        create_time: Process creation time (epoch seconds).
        exe_hash: SHA256 hash of executable, or empty string.
        name: Process name (fallback if exe_hash empty).

    Returns:
        Identity key string.
    """
    stable = exe_hash or name or "unknown"
    return f"{pid}:{create_time:.3f}:{stable}"


def _sanitize_cmdline(cmdline: str) -> str:
    """Sanitize cmdline: strip sensitive params, truncate."""
    if not cmdline:
        return ""
    # Remove common sensitive patterns
    sanitized = re.sub(
        r'(--?(?:password|wallet|user|pass|token|key|secret|auth)\s*)\S+',
        r'\1[REDACTED]',
        cmdline,
        flags=re.IGNORECASE,
    )
    # Remove long hex/base58 strings (wallet addresses)
    sanitized = re.sub(r'\b[48][1-9A-HJ-NP-Za-km-z]{60,}\b', '[WALLET_REDACTED]', sanitized)
    # Truncate
    max_len = 120
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len] + "..."
    return sanitized


def _hash_file(path: str) -> str:
    """SHA256 hash of a file. Returns empty string on failure."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return "sha256:" + h.hexdigest()[:16]
    except (OSError, PermissionError):
        return ""


def _has_libssl(pid: int) -> bool:
    """Check if process maps libssl via /proc/<pid>/maps."""
    try:
        maps_path = f"/proc/{pid}/maps"
        with open(maps_path) as f:
            for line in f:
                if "libssl" in line:
                    return True
    except (OSError, PermissionError):
        pass
    return False


def _count_connections(pid: int) -> tuple[int, int]:
    """Count total and remote network connections for a process.
    Returns (connection_count, remote_count).
    """
    try:
        import psutil
        proc = psutil.Process(pid)
        conns = proc.net_connections(kind='inet')
        total = len(conns)
        remote = sum(1 for c in conns if c.raddr and c.raddr.ip not in ('', '0.0.0.0', '::'))
        return total, remote
    except Exception:
        pass

    # Fallback: count from /proc/<pid>/net/tcp
    try:
        tcp_path = f"/proc/{pid}/net/tcp"
        if os.path.exists(tcp_path):
            with open(tcp_path) as f:
                lines = f.readlines()
            # Skip header
            count = max(0, len(lines) - 1)
            return count, count
    except (OSError, PermissionError):
        pass

    return 0, 0


_KERNEL_THREAD_PREFIXES = (
    "kworker", "kthreadd", "ksoftirqd", "migration",
    "rcu_sched", "rcu_preempt", "rcuog/", "rcuop/", "rcu_tasks",
    "watchdog", "cpuhp", "idle_inject", "kdevtmpfs",
    "khungtaskd", "kblockd", "kswapd", "kcompactd",
    "kintegrityd", "bioset", "kworker/", "kauditd",
    "oom_reaper", "ksmd", "khugepaged", "ecryptfs-",
    "irq/", "pool_workqueue", "kdmflush", "crypto",
    "ata_", "scsi_", "jbd2/", "xfs-", "ext4-",
    "writeback", "zswap", "zswapd",
    "charger_manager", "hci_", "card0-", "i915/",
    "nvidia-", "nv_", "i915/", "drm_", "ttm_",
    "vfio-", "kvm_", "kvm-", "md_", "md/",
    "loop", "dm-", "zd", "zram",
    "netns", "rcu_", "perf_", "bpf-",
    "kblockd", "kstrp", "kalive", "khungtask",
    "devfreq", "deferwq", "idle_inject",
    "acpi_", "button", "edac-", "memtrain",
)


_SYSTEM_SERVICE_NAMES = {
    "systemd-journald", "systemd-udevd", "systemd-oomd",
    "systemd-resolved", "systemd-timesyncd", "VGAuthService",
    "vmtoolsd", "acpid", "avahi-daemon", "rsyslogd",
    "cron", "crond", "snapd", "polkitd", "accounts-daemon",
    "ModemManager", "udisksd", "upowerd", "packagekitd",
    "unattended-upgrade", "cups-browsed", "cupsd",
    "nginx", "apache2", "mysql", "mysqld", "postgres",
    "redis-server", "thermald", "irqbalance", "sssd",
}

_SYSTEM_SERVICE_PATH_PREFIXES = (
    "/usr/lib/systemd/", "/lib/systemd/",
    "/usr/sbin/", "/usr/libexec/",
)


def _is_system_service_like(name: str, exe_path: str, username: str) -> bool:
    """Check if a process looks like a system service/daemon."""
    if name in _SYSTEM_SERVICE_NAMES:
        return True
    if any(exe_path.startswith(p) for p in _SYSTEM_SERVICE_PATH_PREFIXES):
        return True
    if username in ("root", "systemd-network", "systemd-resolve", "messagebus", "avahi"):
        # root processes with daemon-like names
        if name.endswith("d") and len(name) > 3:
            return True
    return False


def _get_username(pid: int) -> str:
    """Get process username. Returns empty string on failure."""
    try:
        import psutil
        return psutil.Process(pid).username() or ""
    except Exception:
        pass
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    import pwd
                    return pwd.getpwuid(uid).pw_name
    except (OSError, ValueError, KeyError, ImportError):
        pass
    return ""


def _is_kernel_thread(name: str) -> bool:
    """Check if a process name looks like a kernel thread."""
    if not name:
        return False
    lower = name.lower()
    return any(lower.startswith(p) for p in _KERNEL_THREAD_PREFIXES)


def _get_runtime_sec(pid: int) -> float:
    """Get process runtime in seconds."""
    try:
        stat_path = f"/proc/{pid}/stat"
        with open(stat_path) as f:
            stat = f.read().split()
        # Field 22 (0-indexed: 21) is starttime in clock ticks
        starttime_ticks = int(stat[21])
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
        hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        start_sec = starttime_ticks / hz
        return uptime - start_sec
    except (OSError, ValueError, IndexError):
        return 0.0


def _sample_cpu_psutil(pids: list[int], interval: float = 0.5) -> dict[int, float]:
    """Sample CPU percent for a list of PIDs using double-sampling.

    psutil.Process.cpu_percent() returns 0.0 on the first call because it
    needs a previous measurement.  We call it once to prime, sleep, then
    call again to get the real value.

    Returns:
        Dict mapping PID to CPU percent.
    """
    import psutil
    result = {}
    procs = {}
    for pid in pids:
        try:
            p = psutil.Process(pid)
            p.cpu_percent()  # prime
            procs[pid] = p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            result[pid] = 0.0
    if procs:
        import time
        time.sleep(interval)
        for pid, p in procs.items():
            try:
                result[pid] = p.cpu_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result[pid] = 0.0
    return result


def scan_processes(config: dict) -> list[dict]:
    """Scan system processes and return sanitized summaries.

    Args:
        config: Configuration dict (not used in first phase, reserved for filtering).

    Returns:
        List of process summary dicts.
    """
    processes = []

    try:
        import psutil
        # First pass: collect basic info and prime cpu_percent
        raw_procs = []
        prime_pids = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'memory_info']):
            try:
                info = proc.info
                pid = info['pid']
                raw_procs.append((proc, info))
                prime_pids.append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Double-sample CPU
        cpu_map = _sample_cpu_psutil(prime_pids, interval=0.5)

        for proc, info in raw_procs:
            try:
                pid = info['pid']
                name = info.get('name', '')
                exe_path = info.get('exe', '') or ''
                cpu_pct = cpu_map.get(pid, 0.0)
                rss = info.get('memory_info', None)
                rss_bytes = rss.rss if rss else 0

                runtime = _get_runtime_sec(pid)
                conn_total, conn_remote = _count_connections(pid)
                libssl = _has_libssl(pid)

                # Read cmdline for hashing (not saved raw)
                cmdline_raw = ""
                try:
                    with open(f"/proc/{pid}/cmdline") as f:
                        cmdline_raw = f.read().replace('\x00', ' ').strip()
                except (OSError, PermissionError):
                    pass

                cmdline_hash = hashlib.sha256(cmdline_raw.encode()).hexdigest()[:16] if cmdline_raw else ""
                cmdline_preview = _sanitize_cmdline(cmdline_raw)
                exe_hash = _hash_file(exe_path) if exe_path else ""

                username = ""
                try:
                    username = proc.username() or ""
                except Exception:
                    pass

                create_time = 0.0
                try:
                    create_time = proc.create_time()
                except Exception:
                    pass

                identity_key = build_process_identity_key(pid, create_time, exe_hash, name)

                processes.append({
                    "pid": pid,
                    "ppid": info.get('ppid', 0),
                    "name": name,
                    "exe_path": exe_path,
                    "exe_hash": exe_hash,
                    "create_time": create_time,
                    "identity_key": identity_key,
                    "username": username,
                    "is_root_process": username == "root",
                    "system_service_like": _is_system_service_like(name, exe_path, username),
                    "cpu_percent": round(cpu_pct, 1),
                    "memory_rss": rss_bytes,
                    "runtime_sec": round(runtime, 1),
                    "connection_count": conn_total,
                    "remote_count": conn_remote,
                    "has_libssl": libssl,
                    "kernel_thread": _is_kernel_thread(name),
                    "cmdline_hash": cmdline_hash,
                    "cmdline_preview_sanitized": cmdline_preview,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except ImportError:
        # Fallback: scan /proc directly
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                with open(f"/proc/{pid}/comm") as f:
                    name = f.read().strip()
            except (OSError, PermissionError):
                continue

            exe_path = ""
            try:
                exe_path = os.readlink(f"/proc/{pid}/exe")
            except (OSError, PermissionError):
                pass

            runtime = _get_runtime_sec(pid)
            conn_total, conn_remote = _count_connections(pid)
            libssl = _has_libssl(pid)

            cmdline_raw = ""
            try:
                with open(f"/proc/{pid}/cmdline") as f:
                    cmdline_raw = f.read().replace('\x00', ' ').strip()
            except (OSError, PermissionError):
                pass

            cmdline_hash = hashlib.sha256(cmdline_raw.encode()).hexdigest()[:16] if cmdline_raw else ""
            cmdline_preview = _sanitize_cmdline(cmdline_raw)
            exe_hash = _hash_file(exe_path) if exe_path else ""

            username = _get_username(pid)

            create_time = 0.0
            try:
                with open(f"/proc/{pid}/stat") as f:
                    stat = f.read().split()
                starttime_ticks = int(stat[21])
                with open("/proc/uptime") as f:
                    uptime = float(f.read().split()[0])
                boot_time = time.time() - uptime
                hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
                create_time = boot_time + starttime_ticks / hz
            except (OSError, ValueError, IndexError):
                pass

            identity_key = build_process_identity_key(pid, create_time, exe_hash, name)

            processes.append({
                "pid": pid,
                "ppid": 0,
                "name": name,
                "exe_path": exe_path,
                "exe_hash": exe_hash,
                "create_time": create_time,
                "identity_key": identity_key,
                "username": username,
                "is_root_process": username == "root",
                "system_service_like": _is_system_service_like(name, exe_path, username),
                "cpu_percent": 0.0,
                "memory_rss": 0,
                "runtime_sec": round(runtime, 1),
                "connection_count": conn_total,
                "remote_count": conn_remote,
                "has_libssl": libssl,
                "kernel_thread": _is_kernel_thread(name),
                "cmdline_hash": cmdline_hash,
                "cmdline_preview_sanitized": cmdline_preview,
            })

    return processes
