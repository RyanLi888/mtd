"""Abnormal traffic correlation records.

Writes process-correlated traffic metadata when protocol evidence is abnormal.
Does not save raw payload, wallet, job_id, nonce, result, or blob.
"""

import hashlib
import json
import os
import socket
from datetime import datetime, timezone

from . import result_mirror


_TRAFFIC_VERDICTS = {"confirmed_mining_live", "protocol_suspicious"}


def _traffic_cfg(config: dict) -> dict:
    return config.get("traffic_alerts", {})


def traffic_alerts_enabled(config: dict) -> bool:
    return _traffic_cfg(config).get("enabled", True)


def _endpoint_hash(ip: str, port: int) -> str:
    raw = f"{ip}:{port}".encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def _addr_parts(addr) -> tuple[str, int]:
    if not addr:
        return "", 0
    ip = getattr(addr, "ip", "")
    port = getattr(addr, "port", 0)
    if not ip and isinstance(addr, tuple) and len(addr) >= 2:
        ip, port = addr[0], addr[1]
    return str(ip or ""), int(port or 0)


def _protocol_from_conn(conn) -> str:
    if conn.type == socket.SOCK_DGRAM:
        return "udp"
    if conn.type == socket.SOCK_STREAM:
        return "tcp"
    return "inet"


def _collect_connections(pid: int, config: dict) -> list[dict]:
    cfg = _traffic_cfg(config)
    privacy = config.get("privacy", {})
    max_connections = int(cfg.get("max_connections", 8))
    save_raw = bool(cfg.get("save_endpoint_raw", privacy.get("save_remote_endpoint_raw", False)))
    conns = []

    try:
        import psutil
        proc = psutil.Process(pid)
        try:
            raw_conns = proc.net_connections(kind="inet")
        except AttributeError:
            raw_conns = proc.connections(kind="inet")
    except Exception:
        raw_conns = []

    for conn in raw_conns:
        local_ip, local_port = _addr_parts(getattr(conn, "laddr", None))
        remote_ip, remote_port = _addr_parts(getattr(conn, "raddr", None))
        if not remote_ip:
            continue

        item = {
            "protocol": _protocol_from_conn(conn),
            "status": getattr(conn, "status", ""),
            "src_endpoint_hash": _endpoint_hash(local_ip, local_port),
            "dst_endpoint_hash": _endpoint_hash(remote_ip, remote_port),
        }
        if save_raw:
            item.update({
                "src_ip": local_ip,
                "src_port": local_port,
                "dst_ip": remote_ip,
                "dst_port": remote_port,
            })
        else:
            item.update({
                "src_ip": "",
                "src_port": 0,
                "dst_ip": "",
                "dst_port": 0,
            })
        conns.append(item)
        if len(conns) >= max_connections:
            break

    return conns


def _evidence(observation: dict) -> dict:
    plain = observation.get("plaintext", {})
    tls = observation.get("tls", {})
    return {
        "compute_evidence_present": observation.get("compute_evidence_present", False),
        "cpu_avg_percent": observation.get("cpu_avg_percent", 0.0),
        "job_marker_count": plain.get("job_marker_count", 0) + tls.get("job_marker_count", 0),
        "submit_marker_count": plain.get("submit_marker_count", 0) + tls.get("submit_marker_count", 0),
        "associated_submit_count": plain.get("associated_submit_count", 0) + tls.get("associated_submit_count", 0),
        "plaintext_job_marker_count": plain.get("job_marker_count", 0),
        "plaintext_submit_marker_count": plain.get("submit_marker_count", 0),
        "plaintext_associated_submit_count": plain.get("associated_submit_count", 0),
        "tls_job_marker_count": tls.get("job_marker_count", 0),
        "tls_submit_marker_count": tls.get("submit_marker_count", 0),
        "tls_associated_submit_count": tls.get("associated_submit_count", 0),
    }


def has_abnormal_traffic_evidence(observation: dict, verdict: dict) -> bool:
    """Return true only when protocol markers indicate abnormal traffic."""
    if verdict.get("verdict", "") not in _TRAFFIC_VERDICTS:
        return False
    ev = _evidence(observation)
    return ev["job_marker_count"] > 0 or ev["submit_marker_count"] > 0


def build_traffic_alert(candidate: dict, observation: dict, verdict: dict,
                        config: dict, run_id: str, observation_path: str = "",
                        alert_path: str = "") -> dict:
    """Build a process-correlated abnormal traffic record."""
    proc = candidate.get("process", {})
    pid = candidate.get("pid", 0)
    ev = _evidence(observation)
    conns = _collect_connections(pid, config)
    primary = conns[0] if conns else {}
    correlation_id = hashlib.sha256(
        f"{run_id}:{pid}:{verdict.get('verdict', '')}:{ev.get('job_marker_count', 0)}:{ev.get('submit_marker_count', 0)}".encode()
    ).hexdigest()[:16]

    severity = "high" if verdict.get("verdict") == "confirmed_mining_live" else "medium"

    return {
        "schema_version": "1.0",
        "record_type": "abnormal_traffic_correlation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "traffic_correlation_id": correlation_id,
        "server": socket.gethostname(),
        "level": severity,
        "action": "inspect_or_stop_process",
        "pid": pid,
        "process": candidate.get("name", ""),
        "process_user": proc.get("username", ""),
        "exe_hash": proc.get("exe_hash", ""),
        "cmdline_hash": proc.get("cmdline_hash", ""),
        "verdict": verdict.get("verdict", ""),
        "confidence": verdict.get("confidence", ""),
        "visibility_mode": verdict.get("visibility_mode", ""),
        "visibility_boundary": verdict.get("visibility_boundary"),
        "src_ip": primary.get("src_ip", ""),
        "dst_ip": primary.get("dst_ip", ""),
        "dst_port": primary.get("dst_port", 0),
        "protocol": primary.get("protocol", ""),
        "endpoint_count": len(conns),
        "endpoints": conns,
        "evidence": ev,
        "links": {
            "observation_json": observation_path,
            "formal_alert_jsonl": alert_path,
        },
        "privacy": {
            "raw_payload_saved": False,
            "endpoint_raw_saved": bool(_traffic_cfg(config).get(
                "save_endpoint_raw", config.get("privacy", {}).get("save_remote_endpoint_raw", False)
            )),
            "wallet_saved": False,
            "job_id_saved": False,
            "nonce_saved": False,
            "result_saved": False,
            "blob_saved": False,
        },
    }


def write_traffic_alert(record: dict, config: dict) -> str:
    """Append one abnormal traffic record to results/traffic_alerts.jsonl."""
    cfg = _traffic_cfg(config)
    filename = cfg.get("filename", "traffic_alerts.jsonl")
    return result_mirror.append_jsonl(config, filename, record)
