"""
Telemetry Acquisition Layer - Gateway Sniffer (Simulated)
=========================================================
Simulates network traffic logs captured at the gateway level.
No agents are installed on endpoints — all monitoring is done centrally.
"""

import random
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any


# Simulated endpoint IPs (no agents on these machines)
ENDPOINT_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12",
    "192.168.1.20", "192.168.1.21", "192.168.1.30",
    "10.0.0.5", "10.0.0.6", "10.0.0.7",
]

# External destination IPs
EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "104.21.45.67", "172.217.14.206",
    "185.220.101.5", "45.33.32.156", "198.51.100.42",
]

# Known-bad C2 server IPs (simulated threat intel)
C2_IPS = [
    "91.108.4.1",    # Simulated Cobalt Strike C2
    "185.234.218.4", # Simulated Emotet C2
    "194.165.16.77", # Simulated AsyncRAT C2
    "45.142.212.100",# Simulated Sliver C2
]

# C2 beacon ports (non-standard, commonly used by malware)
C2_PORTS = [4444, 1337, 8888, 9999, 6666, 2222]

# Admin/lateral movement ports
LATERAL_PORTS = [445, 135, 3389, 5985, 5986, 139]  # SMB, WMI, RDP, WinRM

# Common ports
COMMON_PORTS = [80, 443, 53, 22, 25, 587, 3306, 5432, 8080, 8443]
SCAN_PORTS = list(range(1, 1025))  # ports used in port scan simulation

PROTOCOLS = ["TCP", "UDP", "ICMP"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_normal_traffic(count: int = 5) -> List[Dict[str, Any]]:
    """Generate normal benign network traffic logs."""
    logs = []
    for _ in range(count):
        logs.append({
            "log_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source_ip": random.choice(ENDPOINT_IPS),
            "destination_ip": random.choice(EXTERNAL_IPS),
            "protocol": random.choice(["TCP", "UDP"]),
            "destination_port": random.choice(COMMON_PORTS),
            "bytes_sent": random.randint(100, 50_000),
            "status": "success",
            "traffic_type": "normal",
        })
    return logs


def generate_port_scan(attacker_ip: str = None, count: int = 15) -> List[Dict[str, Any]]:
    """
    Simulate a port scan: same source IP hitting many different ports
    rapidly within a short time window.
    """
    attacker = attacker_ip or random.choice(ENDPOINT_IPS)
    target = random.choice(EXTERNAL_IPS)
    ports = random.sample(SCAN_PORTS, min(count, len(SCAN_PORTS)))
    logs = []
    for port in ports:
        logs.append({
            "log_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source_ip": attacker,
            "destination_ip": target,
            "protocol": "TCP",
            "destination_port": port,
            "bytes_sent": random.randint(40, 200),
            "status": random.choice(["success", "failed"]),
            "traffic_type": "port_scan",
        })
    return logs


def generate_brute_force(attacker_ip: str = None, count: int = 8) -> List[Dict[str, Any]]:
    """
    Simulate brute-force login attempts: repeated failed connections
    to port 22 (SSH) or 3389 (RDP) from same IP.
    """
    attacker = attacker_ip or random.choice(ENDPOINT_IPS)
    target = random.choice(EXTERNAL_IPS)
    login_port = random.choice([22, 3389, 21, 23])
    logs = []
    for _ in range(count):
        logs.append({
            "log_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source_ip": attacker,
            "destination_ip": target,
            "protocol": "TCP",
            "destination_port": login_port,
            "bytes_sent": random.randint(50, 500),
            "status": "failed",
            "traffic_type": "brute_force",
        })
    return logs


def generate_data_exfiltration(source_ip: str = None, count: int = 3) -> List[Dict[str, Any]]:
    """
    Simulate data exfiltration: unusually large outbound data transfers.
    """
    src = source_ip or random.choice(ENDPOINT_IPS)
    logs = []
    for _ in range(count):
        logs.append({
            "log_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source_ip": src,
            "destination_ip": random.choice(EXTERNAL_IPS),
            "protocol": "TCP",
            "destination_port": random.choice([443, 80, 8080]),
            "bytes_sent": random.randint(1_000_001, 50_000_000),
            "status": "success",
            "traffic_type": "data_exfiltration",
        })
    return logs


def generate_c2_beacon(infected_ip: str = None, count: int = 8) -> List[Dict[str, Any]]:
    """
    Simulate Command & Control (C2) beaconing:
    Malware on an endpoint periodically calls back to a C2 server
    at regular intervals on non-standard ports.
    """
    src = infected_ip or random.choice(ENDPOINT_IPS)
    c2_server = random.choice(C2_IPS)
    beacon_port = random.choice(C2_PORTS)
    logs = []
    for _ in range(count):
        logs.append({
            "log_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source_ip": src,
            "destination_ip": c2_server,
            "protocol": "TCP",
            "destination_port": beacon_port,
            "bytes_sent": random.randint(64, 512),   # Small, regular beacon packets
            "status": "success",
            "traffic_type": "c2_beacon",
        })
    return logs


def generate_dns_tunneling(infected_ip: str = None, count: int = 25) -> List[Dict[str, Any]]:
    """
    Simulate DNS tunneling:
    Attacker encodes data inside DNS queries to exfiltrate data or
    maintain C2 comms while bypassing firewall rules.
    High-frequency DNS queries with unusually large payloads.
    """
    src = infected_ip or random.choice(ENDPOINT_IPS)
    dns_server = random.choice(["8.8.8.8", "1.1.1.1", "208.67.222.222"])
    logs = []
    for _ in range(count):
        logs.append({
            "log_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source_ip": src,
            "destination_ip": dns_server,
            "protocol": "UDP",
            "destination_port": 53,
            "bytes_sent": random.randint(500, 2000),  # Abnormally large DNS payloads
            "status": "success",
            "traffic_type": "dns_tunneling",
        })
    return logs


def generate_lateral_movement(attacker_ip: str = None, count: int = 6) -> List[Dict[str, Any]]:
    """
    Simulate lateral movement:
    Compromised internal host probing other internal hosts
    on administrative ports (SMB, WMI, RDP, WinRM).
    """
    src = attacker_ip or random.choice(ENDPOINT_IPS)
    # Target other internal IPs (not the source)
    targets = [ip for ip in ENDPOINT_IPS if ip != src]
    logs = []
    for _ in range(count):
        target = random.choice(targets)
        logs.append({
            "log_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source_ip": src,
            "destination_ip": target,
            "protocol": "TCP",
            "destination_port": random.choice(LATERAL_PORTS),
            "bytes_sent": random.randint(200, 4000),
            "status": random.choice(["success", "failed"]),
            "traffic_type": "lateral_movement",
        })
    return logs


def generate_ransomware_spread(infected_ip: str = None) -> List[Dict[str, Any]]:
    """
    Simulate ransomware spreading across the network:
    Infected host rapidly connects to many internal hosts over SMB (port 445)
    to encrypt shared drives — characteristic of WannaCry, NotPetya, etc.
    """
    src = infected_ip or random.choice(ENDPOINT_IPS)
    targets = [ip for ip in ENDPOINT_IPS if ip != src]
    logs = []
    # Hit every reachable internal host over SMB
    for target in targets:
        logs.append({
            "log_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "source_ip": src,
            "destination_ip": target,
            "protocol": "TCP",
            "destination_port": 445,  # SMB
            "bytes_sent": random.randint(500_000, 5_000_000),  # Large file writes
            "status": "success",
            "traffic_type": "ransomware_spread",
        })
    return logs


def generate_mixed_traffic_batch(
    normal_count: int = 10,
    include_port_scan: bool = True,
    include_brute_force: bool = True,
    include_exfiltration: bool = True,
    include_c2_beacon: bool = True,
    include_dns_tunneling: bool = True,
    include_lateral_movement: bool = True,
    include_ransomware: bool = True,
) -> List[Dict[str, Any]]:
    """
    Generate a realistic mixed batch of network traffic logs
    as would be captured at a network gateway.
    """
    logs = generate_normal_traffic(normal_count)

    if include_port_scan and random.random() > 0.3:
        attacker = random.choice(ENDPOINT_IPS)
        logs.extend(generate_port_scan(attacker_ip=attacker, count=random.randint(11, 20)))

    if include_brute_force and random.random() > 0.4:
        attacker = random.choice(ENDPOINT_IPS)
        logs.extend(generate_brute_force(attacker_ip=attacker, count=random.randint(6, 12)))

    if include_exfiltration and random.random() > 0.5:
        src = random.choice(ENDPOINT_IPS)
        logs.extend(generate_data_exfiltration(source_ip=src, count=random.randint(1, 3)))

    if include_c2_beacon and random.random() > 0.4:
        infected = random.choice(ENDPOINT_IPS)
        logs.extend(generate_c2_beacon(infected_ip=infected, count=random.randint(6, 12)))

    if include_dns_tunneling and random.random() > 0.5:
        infected = random.choice(ENDPOINT_IPS)
        logs.extend(generate_dns_tunneling(infected_ip=infected, count=random.randint(20, 35)))

    if include_lateral_movement and random.random() > 0.5:
        attacker = random.choice(ENDPOINT_IPS)
        logs.extend(generate_lateral_movement(attacker_ip=attacker, count=random.randint(5, 8)))

    if include_ransomware and random.random() > 0.7:
        infected = random.choice(ENDPOINT_IPS)
        logs.extend(generate_ransomware_spread(infected_ip=infected))

    # Shuffle to simulate realistic interleaved traffic
    random.shuffle(logs)
    return logs
