"""
anomaly_detector.py — Detection + automated response + graph storage orchestrator.
"""

import logging
from datetime import datetime

from ingestion.services.risk_engine     import compute_risk
from ingestion.services.response_engine import execute_response, is_blocked
from ingestion.db.neo4j import (
    store_attack_event,
    store_honeypot_redirect,
    store_block_event,
)

logger = logging.getLogger(__name__)


def process_event(ip: str, device: str, request_count: int,
                  timestamp: datetime) -> dict:
    """
    Full real-time pipeline:
        1. Compute weighted risk score (ML+temporal+count+spike+trend).
        2. Execute automated response (flag / block / honeypot).
        3. Store graph relationships in Neo4j.
        4. Return structured result.
    """
    logger.info("INGEST | ip=%-16s device=%-20s count=%d ts=%s",
                ip, device, request_count, timestamp.isoformat())

    # Already blocked — short-circuit
    if is_blocked(ip):
        logger.warning("BLOCKED IP attempted access | ip=%s device=%s", ip, device)
        return {
            "status":       "EXTREME_RISK",
            "risk_score":   100.0,
            "graph_stored": False,
            "components":   {},
            "override_triggered": True,
            "response":     {
                "actions_taken":          ["blocked"],
                "blocked":                True,
                "redirected_to_honeypot": True,
                "honeypot_id":            None,
                "flag_count":             0,
                "reason":                 "previously_blocked",
                "block_expires_at":       None,
                "honeypot_interactions":  0,
            },
            "message": f"EXTREME RISK: {ip} is on the block list.",
        }

    result   = compute_risk(ip, request_count, timestamp)
    score    = result["risk_score"]
    status   = result["status"]
    comps    = result["components"]
    override = result.get("override_triggered", False)
    ts_str   = timestamp.isoformat()

    # Automated response — status is single source of truth
    response = execute_response(ip, score, status, comps)

    _log_result(ip, device, score, status, comps, response, override)

    # ── Graph storage ─────────────────────────────────────────────────────────
    graph_stored = False

    # Always store non-normal events as ATTACKED relationship
    if status != "NORMAL":
        graph_stored = store_attack_event(
            ip=ip, device=device,
            risk_score=score, status=status, timestamp=ts_str,
            ml_score=comps.get("ml_score", 0),
            spike_score=comps.get("spike_score", 0),
            trend_score=comps.get("trend_score", 0),
            temporal_score=comps.get("temporal_score", 0),
            count_score=comps.get("count_score", 0),
            log_score=comps.get("log_score", 0),
        )

    # Store honeypot redirect if triggered
    if "redirected_to_honeypot" in response["actions_taken"]:
        hid = response.get("honeypot_id") or "honeypot_unknown"
        store_honeypot_redirect(
            ip=ip, honeypot_id=hid,
            reason=response["reason"], timestamp=ts_str,
        )

    # Store block event if triggered
    if "blocked" in response["actions_taken"]:
        store_block_event(
            ip=ip, reason=response["reason"], timestamp=ts_str,
        )

    return {
        "status":             status,
        "risk_score":         score,
        "graph_stored":       graph_stored,
        "override_triggered": override,
        "components":         comps,
        "response":           response,
        "message":            _build_message(ip, device, request_count,
                                             score, status, comps, response),
    }


def _log_result(ip, device, score, status, comps, response, override):
    reasons = []
    if comps.get("spike_score", 0) > 70:
        reasons.append(f"spike={comps['spike_score']:.1f}")
    if comps.get("trend_score", 0) > 60:
        reasons.append(f"trend={comps['trend_score']:.1f}")
    if comps.get("ml_score", 0) >= 60:
        reasons.append(f"ml={comps['ml_score']:.1f}")
    if comps.get("temporal_score", 0) >= 50:
        reasons.append(f"rate={comps['temporal_score']:.1f}")
    reason  = " + ".join(reasons) if reasons else "combined"
    actions = ", ".join(response["actions_taken"]) or "none"
    ovr     = " [OVERRIDE]" if override else ""

    if status in ("EXTREME_RISK", "HIGH_RISK"):
        logger.warning("%s%s | ip=%s score=%.2f | reason: %s | actions: %s",
                       status, ovr, ip, score, reason, actions)
    elif status == "SUSPICIOUS":
        logger.warning("SUSPICIOUS%s | ip=%s score=%.2f | reason: %s | actions: %s",
                       ovr, ip, score, reason, actions)
    else:
        logger.info("NORMAL | ip=%s score=%.2f", ip, score)


def _build_message(ip, device, count, score, status, comps, response) -> str:
    reasons = []
    if comps.get("spike_score", 0) > 70:
        reasons.append("sudden spike detected")
    if comps.get("trend_score", 0) > 60:
        reasons.append("escalating trend")
    if comps.get("ml_score", 0) >= 60:
        reasons.append("behavioral anomaly")
    if not reasons:
        reasons.append("within normal parameters")

    actions    = response["actions_taken"]
    action_str = ""
    if "blocked" in actions:
        action_str = " IP BLOCKED and redirected to honeypot."
    elif "redirected_to_honeypot" in actions:
        action_str = f" Redirected to honeypot ({response.get('honeypot_id', '')})."
    elif "flagged" in actions:
        action_str = f" IP flagged (count={response['flag_count']})."

    prefix = {
        "EXTREME_RISK": "EXTREME RISK",
        "HIGH_RISK":    "HIGH RISK",
        "SUSPICIOUS":   "SUSPICIOUS",
        "NORMAL":       "NORMAL",
    }.get(status, status)

    return (f"{prefix}: {count} reqs from {ip} via {device}. "
            f"Score: {score:.1f}/100. {'; '.join(reasons)}.{action_str}")
