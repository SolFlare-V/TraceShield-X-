"""
simulation.py - Log-dataset-driven generator for TraceShield X++
All attack scenarios are derived from the real intrusion_data.csv dataset.
"""

import os
import random
import copy
from typing import List, Dict, Any

DATASET_PATH = os.path.join("backend", "data", "intrusion_data.csv")

# ── Load real dataset rows once at import time ────────────────────────────────

def _load_rows() -> List[Dict[str, Any]]:
    if not os.path.exists(DATASET_PATH):
        return []
    import csv
    with open(DATASET_PATH, newline="") as f:
        rows = list(csv.DictReader(f))
    int_fields   = ["login_attempts","failed_logins","session_duration",
                    "unusual_time_access","network_traffic_volume",
                    "network_packet_size","attack_detected","privilege_escalation","sudo_attempt"]
    float_fields = ["ip_reputation_score"]
    for r in rows:
        for k in int_fields:
            if k in r:
                try: r[k] = int(r[k])
                except: r[k] = 0
        for k in float_fields:
            if k in r:
                try: r[k] = float(r[k])
                except: r[k] = 0.0
    return rows

_ALL_ROWS:    List[Dict[str, Any]] = _load_rows()
_ATTACK_ROWS: List[Dict[str, Any]] = [r for r in _ALL_ROWS if r.get("attack_detected") == 1]
_NORMAL_ROWS: List[Dict[str, Any]] = [r for r in _ALL_ROWS if r.get("attack_detected") == 0]


def generate_attack_scenario() -> Dict[str, Any]:
    """Return a real attack row from the dataset."""
    pool = _ATTACK_ROWS if _ATTACK_ROWS else _ALL_ROWS
    if not pool:
        return _synthetic_attack()
    row = copy.deepcopy(random.choice(pool))
    if not row.get("src_ip") or row["src_ip"] == "127.0.0.1":
        row["src_ip"] = (
            f"10.{random.randint(1,254)}."
            f"{random.randint(1,254)}."
            f"{random.randint(1,254)}"
        )
    return row


def generate_synthetic_logs(n: int = 70) -> List[Dict[str, Any]]:
    """Return rows from the real dataset (shuffled). Falls back to synthetic."""
    if _ALL_ROWS:
        pool = (_ALL_ROWS * (n // len(_ALL_ROWS) + 1))[:n]
        random.shuffle(pool)
        return [copy.deepcopy(r) for r in pool]
    return [_synthetic_normal() if random.random() < 0.7 else _synthetic_attack()
            for _ in range(n)]


def get_all_log_lines() -> List[str]:
    """Return all raw_log lines from the dataset."""
    return [r["raw_log"] for r in _ALL_ROWS if r.get("raw_log")]


# ── Fallback synthetic generators ────────────────────────────────────────────

def _synthetic_normal() -> Dict[str, Any]:
    return {
        "name": "System Event", "src_ip": None,
        "protocol_type": random.choice(["TCP","UDP","HTTP"]),
        "login_attempts": random.randint(1,3), "failed_logins": random.randint(0,1),
        "unusual_time_access": 0, "ip_reputation_score": round(random.uniform(0.0,0.25),4),
        "session_duration": random.randint(30,180),
        "network_traffic_volume": random.randint(500,5000),
        "network_packet_size": random.randint(64,512), "attack_detected": 0,
    }

def _synthetic_attack() -> Dict[str, Any]:
    return {
        "name": "Privilege Escalation", "src_ip": None,
        "protocol_type": "TCP",
        "login_attempts": random.randint(8,15), "failed_logins": random.randint(6,12),
        "unusual_time_access": 1, "ip_reputation_score": round(random.uniform(0.75,0.95),4),
        "session_duration": random.randint(200,600),
        "network_traffic_volume": random.randint(10000,80000),
        "network_packet_size": random.randint(512,2048), "attack_detected": 1,
        "privilege_escalation": 1,
    }


def generate_attack_log_strings(n: int = 100) -> List[str]:
    """Return raw_log lines from the dataset."""
    pool = get_all_log_lines()
    if pool:
        return [random.choice(pool) for _ in range(n)]
    return [f"Apr 11 00:00:00 ubuntu-server sudo: user{i} : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
            for i in range(n)]


def save_synthetic_to_csv(n: int = 70, path: str = "backend/data/synthetic_logs.csv") -> None:
    import pandas as pd
    pd.DataFrame(generate_synthetic_logs(n)).to_csv(path, index=False)
    print(f"Saved {n} rows to {path}")
