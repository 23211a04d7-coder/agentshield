"""
Detection Engine Layer - Rule-Based Threat Detection
=====================================================
Analyzes gateway-captured logs and generates security alerts.
All detection happens centrally — no agents on endpoints.

Rules:
  Rule 1: Port Scan          - >10 connections from same IP in 60s      → HIGH
  Rule 2: Brute Force        - >5 failed logins from same IP in 5m      → HIGH
  Rule 3: Data Exfiltration  - bytes_sent > 1,000,000                   → MEDIUM
  Rule 4: C2 Beacon          - repeated callbacks to same external IP    → CRITICAL
  Rule 5: DNS Tunneling      - >20 large DNS queries from same IP/60s   → HIGH
  Rule 6: Lateral Movement   - internal→internal admin port connections  → HIGH
  Rule 7: Ransomware Spread  - SMB burst to >4 internal hosts           → CRITICAL
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict


LOGIN_PORTS = {21, 22, 23, 25, 110, 143, 389, 3389, 5900}

# Known-bad C2 IPs (must match gateway_sniffer.py)
C2_IPS = {
    "91.108.4.1", "185.234.218.4", "194.165.16.77", "45.142.212.100",
}

# Non-standard ports used by C2 malware
C2_PORTS = {4444, 1337, 8888, 9999, 6666, 2222}

# Internal network prefixes
INTERNAL_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.")

# Admin ports used in lateral movement
LATERAL_PORTS = {445, 135, 3389, 5985, 5986, 139}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(ts_str: str) -> datetime:
    """Parse ISO timestamp string to datetime."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def _make_alert(
    threat_type: str,
    severity: str,
    source_ip: str,
    description: str,
    risk_score: int,
) -> Dict[str, Any]:
    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "threat_type": threat_type,
        "severity": severity,
        "source_ip": source_ip,
        "description": description,
        "risk_score": min(100, max(0, risk_score)),
    }


def detect_port_scan(
    logs: List[Dict[str, Any]],
    threshold: int = 10,
    window_seconds: int = 60,
) -> List[Dict[str, Any]]:
    """
    Rule 1: Port Scan Detection
    If more than `threshold` connections from same IP within `window_seconds` → HIGH alert.
    """
    alerts = []
    # Group logs by source_ip
    ip_logs: Dict[str, List[Dict]] = defaultdict(list)
    for log in logs:
        ip_logs[log["source_ip"]].append(log)

    for ip, ip_log_list in ip_logs.items():
        # Sort by timestamp
        sorted_logs = sorted(ip_log_list, key=lambda x: _parse_ts(x["timestamp"]))
        # Sliding window
        for i, log in enumerate(sorted_logs):
            window_start = _parse_ts(log["timestamp"])
            window_end = window_start + timedelta(seconds=window_seconds)
            ports_in_window = set()
            for j in range(i, len(sorted_logs)):
                ts = _parse_ts(sorted_logs[j]["timestamp"])
                if ts <= window_end:
                    ports_in_window.add(sorted_logs[j]["destination_port"])
                else:
                    break
            if len(ports_in_window) > threshold:
                alerts.append(_make_alert(
                    threat_type="PORT_SCAN",
                    severity="HIGH",
                    source_ip=ip,
                    description=(
                        f"Port scan detected: {len(ports_in_window)} unique ports probed "
                        f"from {ip} within {window_seconds}s window. "
                        f"Ports: {sorted(list(ports_in_window))[:10]}..."
                    ),
                    risk_score=85,
                ))
                break  # One alert per IP per batch

    return alerts


def detect_brute_force(
    logs: List[Dict[str, Any]],
    threshold: int = 5,
    window_minutes: int = 5,
) -> List[Dict[str, Any]]:
    """
    Rule 2: Brute Force Detection
    If more than `threshold` failed login attempts from same IP within `window_minutes` → HIGH alert.
    """
    alerts = []
    ip_failed: Dict[str, List[Dict]] = defaultdict(list)

    for log in logs:
        if (
            log.get("status") == "failed"
            and log.get("destination_port") in LOGIN_PORTS
        ):
            ip_failed[log["source_ip"]].append(log)

    window_delta = timedelta(minutes=window_minutes)

    for ip, failed_logs in ip_failed.items():
        sorted_logs = sorted(failed_logs, key=lambda x: _parse_ts(x["timestamp"]))
        for i, log in enumerate(sorted_logs):
            window_start = _parse_ts(log["timestamp"])
            window_end = window_start + window_delta
            count = sum(
                1 for l in sorted_logs[i:]
                if _parse_ts(l["timestamp"]) <= window_end
            )
            if count > threshold:
                port = log.get("destination_port", "unknown")
                service = _port_to_service(port)
                alerts.append(_make_alert(
                    threat_type="BRUTE_FORCE",
                    severity="HIGH",
                    source_ip=ip,
                    description=(
                        f"Brute force attack detected: {count} failed {service} login attempts "
                        f"from {ip} on port {port} within {window_minutes} minutes."
                    ),
                    risk_score=90,
                ))
                break

    return alerts


def detect_data_exfiltration(
    logs: List[Dict[str, Any]],
    threshold_bytes: int = 1_000_000,
) -> List[Dict[str, Any]]:
    """
    Rule 3: Data Exfiltration Detection
    If bytes_sent > threshold_bytes → MEDIUM alert.
    """
    alerts = []
    seen_ips = set()

    for log in logs:
        bytes_sent = log.get("bytes_sent", 0)
        src_ip = log.get("source_ip", "unknown")
        if bytes_sent > threshold_bytes and src_ip not in seen_ips:
            seen_ips.add(src_ip)
            mb_sent = bytes_sent / (1024 * 1024)
            alerts.append(_make_alert(
                threat_type="DATA_EXFILTRATION",
                severity="MEDIUM",
                source_ip=src_ip,
                description=(
                    f"Potential data exfiltration: {mb_sent:.2f} MB sent from {src_ip} "
                    f"to {log.get('destination_ip', 'unknown')} "
                    f"on port {log.get('destination_port', 'unknown')}."
                ),
                risk_score=70,
            ))

    return alerts


def detect_c2_beacon(
    logs: List[Dict[str, Any]],
    threshold: int = 5,
) -> List[Dict[str, Any]]:
    """
    Rule 4: C2 Beacon Detection
    If an internal IP makes repeated connections to the same known-bad external IP
    on a non-standard port → CRITICAL alert.
    """
    alerts = []
    # Track (source_ip, dest_ip, dest_port) tuples
    beacon_counts: Dict[tuple, int] = defaultdict(int)
    beacon_examples: Dict[tuple, Dict] = {}

    for log in logs:
        dest_ip = log.get("destination_ip", "")
        dest_port = log.get("destination_port", 0)
        src_ip = log.get("source_ip", "")
        # Match known C2 IPs OR non-standard ports to external IPs
        if dest_ip in C2_IPS or (dest_port in C2_PORTS and not dest_ip.startswith(INTERNAL_PREFIXES)):
            key = (src_ip, dest_ip, dest_port)
            beacon_counts[key] += 1
            beacon_examples[key] = log

    for (src_ip, dest_ip, dest_port), count in beacon_counts.items():
        if count >= threshold:
            alerts.append(_make_alert(
                threat_type="C2_BEACON",
                severity="CRITICAL",
                source_ip=src_ip,
                description=(
                    f"C2 beaconing detected: {src_ip} made {count} callbacks to "
                    f"{dest_ip}:{dest_port} — consistent with malware implant "
                    f"(Cobalt Strike / AsyncRAT / Sliver). Isolate endpoint immediately."
                ),
                risk_score=95,
            ))
    return alerts


def detect_dns_tunneling(
    logs: List[Dict[str, Any]],
    threshold: int = 20,
    large_payload_bytes: int = 500,
    window_seconds: int = 60,
) -> List[Dict[str, Any]]:
    """
    Rule 5: DNS Tunneling Detection
    If >threshold DNS (UDP/53) queries with large payloads from same IP in window → HIGH alert.
    """
    alerts = []
    dns_logs: Dict[str, List[Dict]] = defaultdict(list)

    for log in logs:
        if (
            log.get("destination_port") == 53
            and log.get("protocol") == "UDP"
            and log.get("bytes_sent", 0) > large_payload_bytes
        ):
            dns_logs[log["source_ip"]].append(log)

    for ip, ip_logs in dns_logs.items():
        sorted_logs = sorted(ip_logs, key=lambda x: _parse_ts(x["timestamp"]))
        for i, log in enumerate(sorted_logs):
            window_end = _parse_ts(log["timestamp"]) + timedelta(seconds=window_seconds)
            count = sum(
                1 for l in sorted_logs[i:]
                if _parse_ts(l["timestamp"]) <= window_end
            )
            if count >= threshold:
                avg_bytes = sum(l.get("bytes_sent", 0) for l in sorted_logs) // len(sorted_logs)
                alerts.append(_make_alert(
                    threat_type="DNS_TUNNELING",
                    severity="HIGH",
                    source_ip=ip,
                    description=(
                        f"DNS tunneling detected: {ip} sent {count} oversized DNS queries "
                        f"(avg {avg_bytes} bytes) within {window_seconds}s. "
                        f"Normal DNS queries are <100 bytes. Possible data exfiltration or C2 over DNS."
                    ),
                    risk_score=88,
                ))
                break
    return alerts


def detect_lateral_movement(
    logs: List[Dict[str, Any]],
    threshold: int = 4,
) -> List[Dict[str, Any]]:
    """
    Rule 6: Lateral Movement Detection
    If an internal IP connects to multiple other internal IPs on admin ports → HIGH alert.
    """
    alerts = []
    # Map source_ip → set of (dest_ip, dest_port) pairs on admin ports
    lateral_map: Dict[str, set] = defaultdict(set)
    lateral_examples: Dict[str, Dict] = {}

    for log in logs:
        src = log.get("source_ip", "")
        dst = log.get("destination_ip", "")
        port = log.get("destination_port", 0)
        # Both must be internal, and port must be an admin port
        if (
            src.startswith(INTERNAL_PREFIXES)
            and dst.startswith(INTERNAL_PREFIXES)
            and src != dst
            and port in LATERAL_PORTS
        ):
            lateral_map[src].add((dst, port))
            lateral_examples[src] = log

    for src_ip, connections in lateral_map.items():
        unique_targets = {dst for dst, _ in connections}
        if len(unique_targets) >= threshold:
            ports_used = sorted({port for _, port in connections})
            service_names = [_port_to_service(p) for p in ports_used]
            alerts.append(_make_alert(
                threat_type="LATERAL_MOVEMENT",
                severity="HIGH",
                source_ip=src_ip,
                description=(
                    f"Lateral movement detected: {src_ip} connected to "
                    f"{len(unique_targets)} internal hosts via admin protocols "
                    f"({', '.join(service_names)}). "
                    f"Consistent with post-exploitation pivoting (Mimikatz / PsExec / WMI)."
                ),
                risk_score=82,
            ))
    return alerts


def detect_ransomware_spread(
    logs: List[Dict[str, Any]],
    smb_host_threshold: int = 4,
) -> List[Dict[str, Any]]:
    """
    Rule 7: Ransomware Spread Detection
    If one internal IP connects to >smb_host_threshold other internal hosts on SMB (445)
    with large data transfers → CRITICAL alert. Mimics WannaCry / NotPetya behavior.
    """
    alerts = []
    smb_targets: Dict[str, set] = defaultdict(set)
    smb_bytes: Dict[str, int] = defaultdict(int)

    for log in logs:
        src = log.get("source_ip", "")
        dst = log.get("destination_ip", "")
        port = log.get("destination_port", 0)
        if (
            port == 445
            and src.startswith(INTERNAL_PREFIXES)
            and dst.startswith(INTERNAL_PREFIXES)
            and src != dst
        ):
            smb_targets[src].add(dst)
            smb_bytes[src] += log.get("bytes_sent", 0)

    for src_ip, targets in smb_targets.items():
        if len(targets) > smb_host_threshold:
            total_mb = smb_bytes[src_ip] / (1024 * 1024)
            alerts.append(_make_alert(
                threat_type="RANSOMWARE_SPREAD",
                severity="CRITICAL",
                source_ip=src_ip,
                description=(
                    f"Ransomware propagation detected: {src_ip} performed SMB writes to "
                    f"{len(targets)} internal hosts ({total_mb:.1f} MB total). "
                    f"Pattern matches WannaCry/NotPetya lateral encryption. "
                    f"ISOLATE NETWORK SEGMENT IMMEDIATELY."
                ),
                risk_score=98,
            ))
    return alerts


def run_detection(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run all detection rules against a batch of network logs.
    Returns a list of generated alert objects.
    """
    alerts = []
    alerts.extend(detect_port_scan(logs))
    alerts.extend(detect_brute_force(logs))
    alerts.extend(detect_data_exfiltration(logs))
    alerts.extend(detect_c2_beacon(logs))
    alerts.extend(detect_dns_tunneling(logs))
    alerts.extend(detect_lateral_movement(logs))
    alerts.extend(detect_ransomware_spread(logs))
    return alerts


def _port_to_service(port: int) -> str:
    mapping = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        110: "POP3", 143: "IMAP", 389: "LDAP",
        3389: "RDP", 5900: "VNC",
    }
    return mapping.get(port, f"port-{port}")
