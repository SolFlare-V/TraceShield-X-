"""
simulation.py - Synthetic log generator for TraceShield X++
Generates realistic cybersecurity logs for ML training, testing, and live demo.
Distribution: 70% normal, 20% suspicious, 10% attack.
"""

import random
from typing import List, Dict, Any


def _normal_log() -> Dict[str, Any]:
    return {
        "network_packet_size":    random.randint(64, 1500),
        "protocol_type":          random.choice(["TCP", "UDP", "HTTP"]),
        "login_attempts":         random.randint(1, 3),
        "failed_logins":          random.randint(0, 1),
        "unusual_time_access":    0,
        "ip_reputation_score":    round(random.uniform(0.0, 0.25), 4),
        "session_duration":       random.randint(30, 180),
        "network_traffic_volume": random.randint(500, 5000),
        "attack_detected":        0,
    }


def _suspicious_log() -> Dict[str, Any]:
    return {
        "network_packet_size":    random.randint(64, 800),
        "protocol_type":          random.choice(["TCP", "ICMP", "UDP"]),
        "login_attempts":         random.randint(4, 9),
        "failed_logins":          random.randint(2, 5),
        "unusual_time_access":    random.randint(0, 1),
        "ip_reputation_score":    round(random.uniform(0.4, 0.7), 4),
        "session_duration":       random.randint(5, 30),
        "network_traffic_volume": random.randint(100, 800),
        "attack_detected":        0,
    }


def _attack_log() -> Dict[str, Any]:
    return {
        "network_packet_size":    random.randint(1400, 9000),
        "protocol_type":          random.choice(["TCP", "ICMP"]),
        "login_attempts":         random.randint(10, 25),
        "failed_logins":          random.randint(6, 20),
        "unusual_time_access":    1,
        "ip_reputation_score":    round(random.uniform(0.75, 1.0), 4),
        "session_duration":       random.randint(1, 8),
        "network_traffic_volume": random.randint(50000, 500000),
        "attack_detected":        1,
    }


# ── Named attack scenarios for Simulate Attack button ────────────────────────

_ATTACK_SCENARIOS = [
    {
        "name":        "Brute Force SSH",
        "src_ip":      None,   # filled at runtime
        "protocol_type":          "TCP",
        "login_attempts":         random.randint(18, 25),
        "failed_logins":          random.randint(15, 20),
        "unusual_time_access":    1,
        "ip_reputation_score":    round(random.uniform(0.85, 1.0), 4),
        "session_duration":       random.randint(1, 5),
        "network_traffic_volume": random.randint(80000, 200000),
        "network_packet_size":    random.randint(64, 256),
        "attack_detected":        1,
    },
    {
        "name":        "Data Exfiltration",
        "src_ip":      None,
        "protocol_type":          "TCP",
        "login_attempts":         random.randint(2, 4),
        "failed_logins":          random.randint(0, 1),
        "unusual_time_access":    1,
        "ip_reputation_score":    round(random.uniform(0.7, 0.95), 4),
        "session_duration":       random.randint(400, 900),
        "network_traffic_volume": random.randint(300000, 500000),
        "network_packet_size":    random.randint(4000, 9000),
        "attack_detected":        1,
    },
    {
        "name":        "Port Scan / Reconnaissance",
        "src_ip":      None,
        "protocol_type":          "ICMP",
        "login_attempts":         random.randint(1, 3),
        "failed_logins":          random.randint(0, 2),
        "unusual_time_access":    1,
        "ip_reputation_score":    round(random.uniform(0.8, 1.0), 4),
        "session_duration":       random.randint(1, 3),
        "network_traffic_volume": random.randint(50000, 150000),
        "network_packet_size":    random.randint(40, 64),
        "attack_detected":        1,
    },
    {
        "name":        "Privilege Escalation",
        "src_ip":      None,
        "protocol_type":          "TCP",
        "login_attempts":         random.randint(8, 15),
        "failed_logins":          random.randint(6, 12),
        "unusual_time_access":    1,
        "ip_reputation_score":    round(random.uniform(0.75, 0.95), 4),
        "session_duration":       random.randint(200, 600),
        "network_traffic_volume": random.randint(10000, 80000),
        "network_packet_size":    random.randint(512, 2048),
        "attack_detected":        1,
    },
    {
        "name":        "Credential Stuffing",
        "src_ip":      None,
        "protocol_type":          "HTTP",
        "login_attempts":         random.randint(20, 25),
        "failed_logins":          random.randint(18, 24),
        "unusual_time_access":    0,
        "ip_reputation_score":    round(random.uniform(0.8, 1.0), 4),
        "session_duration":       random.randint(1, 10),
        "network_traffic_volume": random.randint(20000, 100000),
        "network_packet_size":    random.randint(256, 1024),
        "attack_detected":        1,
    },
]


def generate_attack_scenario() -> Dict[str, Any]:
    """
    Return a random high-threat attack scenario.
    Always produces SUSPICIOUS / HIGH_RISK / EXTREME_RISK — never NORMAL.
    Used by the Simulate Attack button.
    """
    import copy
    scenario = copy.deepcopy(random.choice(_ATTACK_SCENARIOS))
    # Assign a random attacker IP
    scenario["src_ip"] = (
        f"{random.randint(10,220)}."
        f"{random.randint(1,254)}."
        f"{random.randint(1,254)}."
        f"{random.randint(1,254)}"
    )
    return scenario


def generate_synthetic_logs(n: int = 10000) -> List[Dict[str, Any]]:
    """
    Generate n synthetic network intrusion log records.

    Distribution: 70% normal, 20% suspicious, 10% attack.

    Args:
        n: Number of records to generate. Returns [] if n <= 0.

    Returns:
        Shuffled list of log dicts matching the required schema.
    """
    if n <= 0:
        return []

    random.seed(42)

    n_normal     = int(n * 0.70)
    n_suspicious = int(n * 0.20)
    n_attack     = n - n_normal - n_suspicious

    logs: List[Dict[str, Any]] = (
        [_normal_log()     for _ in range(n_normal)]
        + [_suspicious_log() for _ in range(n_suspicious)]
        + [_attack_log()     for _ in range(n_attack)]
    )

    random.shuffle(logs)
    return logs


def generate_attack_log_strings(n: int = 100) -> List[str]:
    """
    Generate n realistic forensic log strings for demo and testing.

    Args:
        n: Number of log strings to generate.

    Returns:
        List of log string entries.
    """
    if n <= 0:
        return []

    templates = [
        "User executed rm -rf /var/log/auth.log",
        "sudo su executed by non-root user",
        "Multiple failed logins from 192.168.1.{ip}",
        "Log cleared by process PID {pid}",
        "chmod 777 applied to /etc/passwd",
        "Brute force detected from IP {a}.{b}.{c}.{d}",
        "Normal user login at {hour:02d}:{minute:02d}",
        "File read by user USER_{uid}",
    ]

    entries: List[str] = []
    for _ in range(n):
        tpl = random.choice(templates)
        entry = tpl.format(
            ip=random.randint(1, 254),
            pid=random.randint(1000, 9999),
            a=random.randint(1, 254),
            b=random.randint(1, 254),
            c=random.randint(1, 254),
            d=random.randint(1, 254),
            hour=random.randint(0, 23),
            minute=random.randint(0, 59),
            uid=random.randint(1, 99),
        )
        entries.append(entry)

    return entries


def save_synthetic_to_csv(
    n: int = 5000,
    path: str = "backend/data/synthetic_logs.csv",
) -> None:
    """
    Generate synthetic logs and save them to a CSV file.

    Args:
        n:    Number of records to generate.
        path: Output file path.
    """
    import pandas as pd

    logs = generate_synthetic_logs(n)
    df = pd.DataFrame(logs)
    df.to_csv(path, index=False)
    print(f"Saved {len(df)} synthetic logs to {path}")
