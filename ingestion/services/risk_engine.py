"""
risk_engine.py — Adaptive weighted risk scoring with spike override and trend detection.

Weights:
    ML score       → 35%
    Temporal score → 25%
    Count score    → 20%
    Spike score    → 10%
    Trend score    → 10%

Spike override:
    spike_score > 70 → immediate HIGH_RISK regardless of other scores

Classification:
    0–30   → NORMAL
    30–70  → SUSPICIOUS
    70–100 → HIGH_RISK
"""

import logging
from collections import defaultdict, deque
from datetime import datetime

from ingestion.services.ml_model  import get_ml_score, ML_ANOMALY_THRESHOLD
from ingestion.services.ip_memory import record_event

logger = logging.getLogger(__name__)

W_ML       = 0.35
W_TEMPORAL = 0.25
W_COUNT    = 0.20
W_SPIKE    = 0.10
W_TREND    = 0.10

SPIKE_OVERRIDE_THRESHOLD = 70.0   # instant HIGH_RISK
_WINDOW_SECONDS = 60
_ip_window: dict = defaultdict(lambda: deque())


# ── Count score ───────────────────────────────────────────────────────────────

def _count_score(request_count: int) -> float:
    if request_count <= 10:   return 0.0
    if request_count <= 50:   return 15.0
    if request_count <= 100:  return 35.0
    if request_count <= 300:  return 60.0
    if request_count <= 1000: return 80.0
    return 100.0


# ── Temporal score ────────────────────────────────────────────────────────────

def _temporal_score(ip: str, request_count: int, timestamp: datetime) -> float:
    now_ts = timestamp.timestamp()
    window = _ip_window[ip]
    for _ in range(request_count):
        window.append(now_ts)
    cutoff = now_ts - _WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()

    rps = len(window) / _WINDOW_SECONDS
    if rps <= 0:    rps_score = 0.0
    elif rps <= 1:  rps_score = rps * 20.0
    elif rps <= 5:  rps_score = 20.0 + (rps - 1) * 10.0
    elif rps <= 10: rps_score = 60.0 + (rps - 5) * 8.0
    else:           rps_score = 100.0

    h = timestamp.hour
    if 0 <= h <= 5:     tod_mult = 1.40
    elif 22 <= h <= 23: tod_mult = 1.25
    elif 6 <= h <= 8:   tod_mult = 1.10
    else:               tod_mult = 1.00

    return round(min(rps_score * tod_mult, 100.0), 2)


# ── Spike score ───────────────────────────────────────────────────────────────

def _spike_score(avg_count: float, request_count: int) -> tuple:
    """
    Normalized spike ratio:
        spike_ratio = (current - avg) / (avg + 1e-5)
        spike_score = min(spike_ratio * 100, 100)

    Returns (spike_score, spike_ratio).
    """
    spike_ratio = (request_count - avg_count) / (avg_count + 1e-5)
    spike_ratio = max(spike_ratio, 0.0)          # ignore drops
    score = min(spike_ratio * 100.0, 100.0)
    return round(score, 2), round(spike_ratio, 4)


# ── Final weighted score ──────────────────────────────────────────────────────

def compute_risk(ip: str, request_count: int, timestamp: datetime) -> dict:
    """
    Compute adaptive weighted risk score with spike override and trend detection.

    Formula:
        final = 0.35*ml + 0.25*temporal + 0.20*count + 0.10*spike + 0.10*trend

    Overrides:
        spike_score > 70  → HIGH_RISK immediately
        ml_score >= threshold and final < 30 → floor at 30
    """
    rec       = record_event(ip, request_count, timestamp)
    avg_count = rec.avg_count()
    hist_rate = rec.avg_rate()
    t_score_val = rec.trend_score()

    spike, spike_ratio = _spike_score(avg_count, request_count)

    # Deviation for ML features
    deviation = spike_ratio

    ml_score = get_ml_score(
        request_count, timestamp,
        deviation=deviation,
        hist_rate=hist_rate,
    )
    t_score = _temporal_score(ip, request_count, timestamp)
    c_score = _count_score(request_count)

    # Spike override — immediate HIGH_RISK
    if spike > SPIKE_OVERRIDE_THRESHOLD:
        logger.warning(
            "SPIKE OVERRIDE | ip=%s spike=%.1f (%.1fx avg=%.1f) → HIGH_RISK",
            ip, spike, spike_ratio, avg_count
        )
        final  = max(
            W_ML * ml_score + W_TEMPORAL * t_score +
            W_COUNT * c_score + W_SPIKE * spike + W_TREND * t_score_val,
            70.0   # floor at HIGH_RISK boundary
        )
        status = "HIGH_RISK"
    else:
        final = (W_ML * ml_score + W_TEMPORAL * t_score +
                 W_COUNT * c_score + W_SPIKE * spike + W_TREND * t_score_val)

        # ML anomaly override — never NORMAL
        if ml_score >= ML_ANOMALY_THRESHOLD and final < 30.0:
            final = 30.0

        final = round(min(max(final, 0.0), 100.0), 2)

        if final >= 70.0:
            status = "HIGH_RISK"
        elif final >= 30.0:
            status = "SUSPICIOUS"
        else:
            status = "NORMAL"

    final = round(min(max(final, 0.0), 100.0), 2)

    logger.info(
        "RISK | ip=%-16s count=%4d avg=%.1f spike=%.1f(%.2fx) trend=%.1f | "
        "ml=%.1f temporal=%.1f count=%.1f → FINAL=%.2f [%s]",
        ip, request_count, avg_count, spike, spike_ratio, t_score_val,
        ml_score, t_score, c_score, final, status
    )

    return {
        "risk_score": final,
        "status":     status,
        "components": {
            "ml_score":       round(ml_score, 2),
            "temporal_score": round(t_score, 2),
            "count_score":    round(c_score, 2),
            "spike_score":    spike,
            "trend_score":    t_score_val,
            "avg_previous":   round(avg_count, 2),
            "spike_ratio":    spike_ratio,
        },
    }
