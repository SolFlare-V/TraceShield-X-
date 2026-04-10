"""
anomaly.py — Real-time anomaly detection service.
Extensible: swap the rule with an ML model later without changing the API layer.
"""

import logging
from datetime import datetime

from ingestion.db.neo4j_conn import store_suspicious_activity

logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = 100  # request_count above this → anomaly


def process_event(ip: str, device: str, request_count: int, timestamp: datetime) -> dict:
    """
    Process a single ingestion event in real time.

    Steps:
        1. Apply anomaly rule.
        2. If anomaly, persist to Neo4j.
        3. Return structured result.

    Args:
        ip:            Source IP address.
        device:        Device identifier.
        request_count: Number of requests observed.
        timestamp:     Event timestamp.

    Returns:
        Dict with anomaly flag, message, and graph_stored status.
    """
    logger.info("Received event | ip=%s device=%s request_count=%d", ip, device, request_count)

    anomaly = request_count > ANOMALY_THRESHOLD
    graph_stored = False

    if anomaly:
        logger.warning("ANOMALY DETECTED | ip=%s device=%s request_count=%d", ip, device, request_count)
        ts_str = timestamp.isoformat()
        graph_stored = store_suspicious_activity(ip, device, request_count, ts_str)

    return {
        "anomaly":      anomaly,
        "graph_stored": graph_stored,
        "message":      (
            f"Anomaly detected: {request_count} requests from {ip} via {device}."
            if anomaly else
            f"Normal activity from {ip} via {device}."
        ),
    }
