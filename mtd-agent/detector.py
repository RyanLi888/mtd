#!/usr/bin/env python3
"""MTD Linux 检测代理：采集 CPU、进程和网络连接并输出单行 JSON。"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

try:
    import psutil
except ImportError as exc:  # pragma: no cover - deployment guard
    raise SystemExit("缺少 psutil，请执行 pip install -r requirements.txt") from exc

try:
    import yaml
except ImportError:
    yaml = None


ROOT = Path(__file__).resolve().parent
KNOWN_MINERS = {"xmrig", "minerd", "cpuminer", "cgminer", "bfgminer", "ethminer", "phoenixminer", "nbminer", "t-rex"}
SUSPICIOUS_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14444}
SYSTEM_ALLOWLIST = {"systemd", "kthreadd", "ksoftirqd", "migration", "sshd", "dockerd", "containerd"}


def load_settings() -> dict:
    settings_file = ROOT / "config" / "settings.yaml"
    if yaml is None or not settings_file.exists():
        return {}
    with settings_file.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle) or {}
        return value if isinstance(value, dict) else {}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def bounded_text(value: object, limit: int = 512) -> str:
    return str(value or "")[:limit]


def process_snapshot(sample_seconds: float) -> tuple[float, list[dict]]:
    processes = []
    for process in psutil.process_iter(["pid", "name", "username", "cmdline", "memory_percent", "create_time"]):
        try:
            process.cpu_percent(None)
            processes.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    total_cpu = psutil.cpu_percent(interval=sample_seconds)
    snapshot = []
    now = time.time()
    for process in processes:
        try:
            info = process.info
            name = bounded_text(info.get("name"), 128)
            command = bounded_text(" ".join(info.get("cmdline") or []))
            snapshot.append({
                "pid": info["pid"],
                "name": name,
                "cpu": round(process.cpu_percent(None), 2),
                "memory": round(float(info.get("memory_percent") or 0), 2),
                "runtime_seconds": max(0, int(now - float(info.get("create_time") or now))),
                "username": bounded_text(info.get("username"), 64),
                "command": command,
                "known_signature": any(token in f"{name} {command}".lower() for token in KNOWN_MINERS)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    snapshot.sort(key=lambda item: item["cpu"], reverse=True)
    return round(total_cpu, 2), snapshot[:30]


def parse_endpoint(endpoint: str) -> tuple[str, int]:
    endpoint = endpoint.strip()
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint[1:].rsplit("]:", 1)
    else:
        host, _, port = endpoint.rpartition(":")
    try:
        return host.strip("[]"), int(port)
    except ValueError:
        return host.strip("[]"), 0


def network_snapshot() -> list[dict]:
    if not shutil.which("ss"):
        return []
    completed = subprocess.run(
        ["ss", "-tunapH"], capture_output=True, text=True, timeout=8, check=False
    )
    connections = []
    for line in completed.stdout.splitlines():
        fields = line.split(maxsplit=6)
        if len(fields) < 6:
            continue
        remote_ip, remote_port = parse_endpoint(fields[5])
        if not remote_ip or remote_ip in {"*", "0.0.0.0", "::"}:
            continue
        try:
            address = ipaddress.ip_address(remote_ip.split("%", 1)[0])
            if address.is_loopback:
                continue
        except ValueError:
            pass
        process_info = fields[6] if len(fields) > 6 else ""
        process_match = re.search(r'\("([^"]+)"', process_info)
        pid_match = re.search(r"pid=(\d+)", process_info)
        connections.append({
            "protocol": fields[0],
            "state": fields[1],
            "remote_ip": bounded_text(remote_ip, 128),
            "remote_port": remote_port,
            "process": bounded_text(process_match.group(1) if process_match else "", 128),
            "pid": int(pid_match.group(1)) if pid_match else None,
            "suspicious_port": remote_port in SUSPICIOUS_PORTS
        })
    return connections[:200]


def yara_matches(processes: list[dict]) -> list[dict]:
    rule_file = ROOT / "config" / "yara_rules" / "mining.yar"
    if not shutil.which("yara") or not rule_file.exists():
        return []
    matches = []
    for process in processes[:15]:
        executable = Path(f"/proc/{process['pid']}/exe")
        if not executable.exists():
            continue
        try:
            completed = subprocess.run(
                ["yara", str(rule_file), str(executable)],
                capture_output=True, text=True, timeout=3, check=False
            )
            if completed.returncode == 0 and completed.stdout.strip():
                matches.append({"pid": process["pid"], "rules": completed.stdout.strip().splitlines()[:10]})
        except (subprocess.TimeoutExpired, PermissionError):
            continue
    return matches


def analyze(total_cpu: float, processes: list[dict], connections: list[dict], full: bool, settings: dict) -> dict:
    detection_settings = settings.get("detection", {})
    cpu_threshold = float(detection_settings.get("cpu_threshold", 80))
    process_threshold = float(detection_settings.get("process_cpu_threshold", 50))
    suspicious_processes = [
        process for process in processes
        if process["known_signature"] or (process["cpu"] >= process_threshold and process["name"].lower() not in SYSTEM_ALLOWLIST)
    ]
    suspicious_connections = [
        connection for connection in connections
        if connection["suspicious_port"] or any(token in connection["process"].lower() for token in KNOWN_MINERS)
    ]
    matches = yara_matches(processes) if full else []

    score = 0.0
    if any(process["known_signature"] for process in suspicious_processes):
        score += 0.72
    if matches:
        score += 0.85
    if suspicious_connections:
        score += min(0.45, 0.18 + len(suspicious_connections) * 0.05)
    if total_cpu >= cpu_threshold:
        score += 0.12
    if any(process["cpu"] >= 70 for process in suspicious_processes):
        score += 0.22
    score = round(min(score, 1.0), 3)

    if score >= 0.9:
        level = "high"
    elif score >= 0.6:
        level = "medium"
    elif score >= 0.3:
        level = "low"
    else:
        level = "safe"

    return {
        "detection_result": {
            "level": level,
            "score": score,
            "confidence": round(min(0.99, 0.45 + score * 0.55), 3),
            "engine": "heuristic+yara" if full else "heuristic"
        },
        "cpu": {
            "total_percent": total_cpu,
            "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else [],
            "suspicious": bool(suspicious_processes),
            "suspicious_processes": suspicious_processes[:15],
            "top_processes": processes[:10]
        },
        "network": {
            "suspicious": bool(suspicious_connections),
            "suspicious_connections": suspicious_connections[:30],
            "connection_count": len(connections)
        },
        "yara": {"enabled": full and shutil.which("yara") is not None, "matches": matches},
        "recommendations": recommendations(level, suspicious_processes, suspicious_connections)
    }


def recommendations(level: str, processes: list[dict], connections: list[dict]) -> list[str]:
    result = []
    if processes:
        result.append("核验高 CPU 或命中特征的进程，确认后再终止。")
    if connections:
        result.append("核验可疑远端 IP，确认属于矿池后再执行封禁。")
    if level in {"medium", "high"}:
        result.append("执行完整检测并保留进程、网络和文件证据。")
    return result or ["当前未发现明显挖矿特征，继续观察时序变化。"]


def main() -> int:
    parser = argparse.ArgumentParser(description="MTD Linux mining detector")
    parser.add_argument("--mode", choices=("quick", "full"), default="quick")
    parser.add_argument("--server-id", default=os.uname().nodename)
    args = parser.parse_args()
    started = time.monotonic()
    try:
        settings = load_settings()
        detection_settings = settings.get("detection", {})
        global SUSPICIOUS_PORTS
        SUSPICIOUS_PORTS = set(int(port) for port in detection_settings.get("suspicious_ports", SUSPICIOUS_PORTS))
        quick_sample = float(detection_settings.get("sample_seconds", 0.5))
        total_cpu, processes = process_snapshot(max(0.1, 1.5 if args.mode == "full" else quick_sample))
        connections = network_snapshot()
        result = analyze(total_cpu, processes, connections, args.mode == "full", settings)
        response = {
            "status": "ok",
            "timestamp": utc_now(),
            "server_id": args.server_id,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "result": result,
            "error_msg": ""
        }
        print(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Exception as error:  # protocol-level failure response
        print(json.dumps({
            "status": "error", "timestamp": utc_now(), "server_id": args.server_id,
            "result": {}, "error_msg": bounded_text(error, 1000)
        }, ensure_ascii=False, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
