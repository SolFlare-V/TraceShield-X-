"""
ml_model.py — Isolation Forest ML inference with adaptive features.

Features (8):
    0  request_count          — raw volume
    1  log1p_request_count    — log-scaled volume
    2  hour_of_day            — temporal context
    3  is_night               — off-hours flag
    4  is_weekend             — weekend flag
    5  requests_per_second    — rate proxy
    6  burst_flag             — hard burst signal
    7  deviation_from_avg     — behavioral deviation (new)
    8  historical_rate        — historical RPS baseline (new)
"""

import logging
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

_model:  IsolationForest = None
_scaler: StandardScaler  = None

ML_ANOMALY_THRESHOLD = 60.0   # scores above this = anomalous


def _build_features(request_count: int, hour: int, is_night: int,
                    is_weekend: int, burst: int,
                    deviation: float = 0.0,
                    hist_rate: float = 0.0) -> np.ndarray:
    return np.array([[
        request_count,
        np.log1p(request_count),
        hour,
        is_night,
        is_weekend,
        request_count / 60.0,
        burst,
        deviation,
        hist_rate,
    ]])


def _train() -> None:
    global _model, _scaler
    import random
    random.seed(42)
    np.random.seed(42)

    rows = []

    # 80% normal — low counts, business hours, low deviation
    for _ in range(6400):
        c   = int(np.clip(np.random.lognormal(3.5, 0.8), 1, 95))
        h   = random.randint(8, 20)
        dev = random.uniform(-0.2, 0.2)   # small deviation
        hr  = random.uniform(0.1, 1.5)
        rows.append(_build_features(c, h, 0,
                                    int(random.randint(0,4) >= 5),
                                    0, dev, hr)[0])

    # 20% attack — high counts, off-hours, large deviation
    for _ in range(1600):
        c   = int(np.clip(np.random.lognormal(5.5, 1.0), 101, 5000))
        h   = random.choice(list(range(0, 6)) + list(range(22, 24)))
        dev = random.uniform(2.0, 10.0)   # large spike
        hr  = random.uniform(5.0, 50.0)
        rows.append(_build_features(c, h, 1,
                                    random.randint(0, 1),
                                    1, dev, hr)[0])

    X = np.array(rows)
    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)
    _model = IsolationForest(n_estimators=300, contamination=0.20,
                             max_features=0.85, random_state=42)
    _model.fit(X_scaled)
    logger.info("ML model trained on %d samples (9 features).", len(X))


def get_ml_score(request_count: int, timestamp: datetime,
                 deviation: float = 0.0,
                 hist_rate: float = 0.0) -> float:
    """
    Returns ML anomaly score normalized to 0-100.
    Higher = more anomalous.

    Args:
        request_count: Current request count.
        timestamp:     Event timestamp.
        deviation:     Normalized deviation from IP historical average.
        hist_rate:     Historical requests-per-second baseline for this IP.
    """
    global _model, _scaler
    if _model is None:
        _train()

    h          = timestamp.hour
    is_night   = 1 if (h <= 6 or h >= 22) else 0
    is_weekend = 1 if timestamp.weekday() >= 5 else 0
    burst      = 1 if request_count > 200 else 0

    x = _build_features(request_count, h, is_night, is_weekend,
                        burst, deviation, hist_rate)
    x_scaled = _scaler.transform(x)

    raw   = _model.decision_function(x_scaled)[0]
    score = (1 - (raw + 0.5)) * 100
    return float(np.clip(score, 0.0, 100.0))
