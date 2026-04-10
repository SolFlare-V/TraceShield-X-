"""
anomaly_detector.py — Final decision logic with adaptive behavioral context.
"""

import logging
from datetime import datetime

from ingestion.services.risk_engine import compute_risk
from ingestion.db.neo4j_conn import store_suspicious_activity

logger = logging.getLogger(__name__)


def process_event(ip: str, device: str, request_count: int,
                  timestamp: datetime) -> dict:
    logger.info("INGEST | ip=%-16s device=%-20s count=%d ts=%s",
                ip, device, request_count, timestamp.isoformat())

    result = compute_risk(ip, request_count, timestamp)
    score  = result["risk_score"]
    status = result["status"]
    comps  = result["components"]

    _log_result(ip, device, score, status, comps)

    graph_stored = False
    if status in ("SUSPICIOUS", "HIGH_RISK"):
        graph_stored = store_suspicious_activity(
            ip=ip, device=device,
            request_count=request_count,
            timestamp=timestamp.isoformat(),
            risk_score=score, status=status,
            ml_score=comps["ml_score"],
            temporal_score=comps["temporal_score"],
            count_score=comps["count_score"],
            spike_score=comps.get("spike_score", 0.0),
        )

    return {
        "status":       status,
        "risk_score":   score,
        "graph_stored": graph_stored,
        "components":   comps,
        "message":      _build_message(ip, device, request_count,
                                       score, status, comps),
    }


def _log_result(ip, device, score, status, comps):
    avg   = comps.get("avg_previous", 0)
    dev   = comps.get("deviation", 0)
    spike = comps.get("spike_score", 0)

    reasons = []
    if comps["ml_score"] >= 60:
        reasons.append(f"ML anomaly ({comps['ml_score']:.1f})")
    if comps["temporal_score"] >= 50:
        reasons.append(f"high rate ({comps['temporal_score']:.1f})")
    if spike >= 50:
        reasons.append(f"spike {dev:.1f}x above avg {avg:.0f}")
    if comps["count_score"] >= 60:
        reasons.append(f"high volume ({comps['count_score']:.1f})")

    reason = " + ".join(reasons) if reasons else "within baseline"

    if status == "HIGH_RISK":
        logger.warning(
            "HIGH_RISK | ip=%s device=%s score=%.2f | %s "
            "| hist_avg=%.1f deviation=%.2fx spike=%.1f",
            ip, device, score, reason, avg, max(dev, 0), spike
        )
    elif status == "SUSPICIOUS":
        logger.warning(
            "SUSPICIOUS | ip=%s device=%s score=%.2f | %s "
            "| hist_avg=%.1f deviation=%.2fx",
            ip, device, score, reason, avg, max(dev, 0)
        )
    else:
        logger.info("NORMAL | ip=%s device=%s score=%.2f | hist_avg=%.1f",
                    ip, device, score, avg)


def _build_message(ip, device, count, score, status, comps) -> str:
    avg = comps.get("avg_previous", 0)
    dev = comps.get("deviation", 0)

    reasons = []
    if comps["ml_score"] >= 60:
        reasons.append("behavioral anomaly detected by ML")
    if comps.get("spike_score", 0) >= 50:
        reasons.append(f"spike {dev:.1f}x above historical avg ({avg:.0f})")
    if comps["temporal_score"] >= 50:
        reasons.append("abnormal request rate")
    if not reasons:
        reasons.append("within normal parameters")

    prefix = {"HIGH_RISK": "HIGH RISK", "SUSPICIOUS": "SUSPICIOUS",
              "NORMAL": "NORMAL"}[status]
    return (f"{prefix}: {count} requests from {ip} via {device}. "
            f"Risk: {score:.1f}/100. {'; '.join(reasons)}.")
