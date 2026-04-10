"""
anomaly_detector.py — Detection + automated response orchestrator.
"""

import logging
from datetime import datetime

from ingestion.services.risk_engine     import compute_risk
from ingestion.services.response_engine import execute_response, is_blocked
from ingestion.db.neo4j_conn            import store_suspicious_activity

logger = logging.getLogger(__name__)


def process_event(ip: str, device: str, request_count: int,
                  timestamp: datetime) -> dict:
    """
    Full real-time pipeline:
        1. Compute weighted risk score (ML+temporal+count+spike+trend).
        2. Execute automated response (flag / block / honeypot).
        3. Persist to Neo4j.
        4. Return structured result.
    """
    logger.info("INGEST | ip=%-16s device=%-20s count=%d ts=%s",
                ip, device, request_count, timestamp.isoformat())

    # Already blocked — short-circuit
    if is_blocked(ip):
        logger.warning("BLOCKED IP attempted access | ip=%s device=%s", ip, device)
        return {
            "status":       "HIGH_RISK",
            "risk_score":   100.0,
            "graph_stored": False,
            "components":   {},
            "response":     {"actions_taken": ["blocked"], "blocked": True,
                             "redirected_to_honeypot": True,
                             "flag_count": 0, "reason": "previously_blocked"},
            "message":      f"BLOCKED: {ip} is on the block list.",
        }

    result = compute_risk(ip, request_count, timestamp)
    score  = result["risk_score"]
    status = result["status"]
    comps  = result["components"]

    # Automated response — status is the single source of truth
    response = execute_response(ip, score, status, comps)

    _log_result(ip, device, score, status, comps, response)

    # Persist non-normal events
    graph_stored = False
    if status in ("SUSPICIOUS", "HIGH_RISK", "EXTREME_RISK"):
        graph_stored = store_suspicious_activity(
            ip=ip, device=device,
            request_count=request_count,
            timestamp=timestamp.isoformat(),
            risk_score=score, status=status,
            ml_score=comps.get("ml_score", 0),
            temporal_score=comps.get("temporal_score", 0),
            count_score=comps.get("count_score", 0),
            spike_score=comps.get("spike_score", 0),
        )

    return {
        "status":       status,
        "risk_score":   score,
        "graph_stored": graph_stored,
        "components":   comps,
        "response":     response,
        "message":      _build_message(ip, device, request_count,
                                       score, status, comps, response),
    }


def _log_result(ip, device, score, status, comps, response):
    reasons = []
    if comps.get("spike_score", 0) > 70:
        reasons.append(f"spike={comps['spike_score']:.1f}")
    if comps.get("trend_score", 0) > 60:
        reasons.append(f"trend={comps['trend_score']:.1f}")
    if comps.get("ml_score", 0) >= 60:
        reasons.append(f"ml={comps['ml_score']:.1f}")
    if comps.get("temporal_score", 0) >= 50:
        reasons.append(f"rate={comps['temporal_score']:.1f}")
    reason = " + ".join(reasons) if reasons else "combined"

    actions = ", ".join(response["actions_taken"]) or "none"

    if status == "HIGH_RISK":
        logger.warning(
            "HIGH_RISK | ip=%s score=%.2f | reason: %s | actions: %s",
            ip, score, reason, actions
        )
    elif status == "SUSPICIOUS":
        logger.warning(
            "SUSPICIOUS | ip=%s score=%.2f | reason: %s | actions: %s",
            ip, score, reason, actions
        )
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

    actions = response["actions_taken"]
    action_str = ""
    if "blocked" in actions:
        action_str = " IP has been BLOCKED and redirected to honeypot."
    elif "flagged" in actions:
        action_str = f" IP flagged (count={response['flag_count']})."

    prefix = {"HIGH_RISK": "HIGH RISK", "SUSPICIOUS": "SUSPICIOUS",
              "NORMAL": "NORMAL", "EXTREME_RISK": "EXTREME RISK"}.get(status, status)
    return (f"{prefix}: {count} reqs from {ip} via {device}. "
            f"Score: {score:.1f}/100. {'; '.join(reasons)}.{action_str}")
