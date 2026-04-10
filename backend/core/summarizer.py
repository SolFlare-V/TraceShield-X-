"""
summarizer.py — AI-style forensic summarizer for TraceShield X++
Converts raw ML + rule-based output into human-readable analyst reports.
No external APIs — fully local rule-driven generation.
"""

from typing import Dict, Any, List


_RISK_OPENER = {
    "CRITICAL": "CRITICAL risk detected.",
    "HIGH":     "HIGH risk detected.",
    "MEDIUM":   "MEDIUM risk detected.",
    "LOW":      "LOW risk. System activity appears normal.",
}

_RISK_RECOMMENDATION = {
    "CRITICAL": "Immediate investigation required.",
    "HIGH":     "Potential threat — monitor closely.",
    "MEDIUM":   "Suspicious activity detected — review recommended.",
    "LOW":      "System behavior appears normal.",
}

_FLAG_TIMELINE = {
    "BRUTE_FORCE":       "Multiple failed login attempts detected",
    "LOW_REPUTATION_IP": "Connection from suspicious IP address",
    "ODD_ACCESS_TIME":   "Access during unusual hours",
    "LONG_SESSION":      "Unusually long session detected",
}


def generate_summary(
    risk_result: Dict[str, Any],
    detection_result: Dict[str, Any],
    anomaly: bool,
) -> str:
    """
    Generate a concise human-readable forensic summary.

    Args:
        risk_result:      Output of calculate_risk() — must contain "risk_level".
        detection_result: Output of summarize_alerts() — must contain "flags".
        anomaly:          True if ML model flagged the record as anomalous.

    Returns:
        A 1–3 sentence professional summary string.
    """
    risk_level = risk_result.get("risk_level", "LOW")
    flags      = detection_result.get("flags", [])

    parts: List[str] = []

    # 1. Risk level opener
    parts.append(_RISK_OPENER.get(risk_level, "Risk level unknown."))

    # 2. ML anomaly insight
    if anomaly:
        parts.append("Anomalous behavior detected by the ML model.")
    else:
        parts.append("No anomaly detected by the ML model.")

    # 3. Rule explanation
    if flags:
        parts.append(f"Triggered rules: {', '.join(flags)}.")
    else:
        parts.append("No suspicious rules were triggered.")

    # 4. Recommendation
    parts.append(_RISK_RECOMMENDATION.get(risk_level, ""))

    return " ".join(p for p in parts if p)


def generate_timeline(flags: List[str]) -> List[str]:
    """
    Convert a list of rule flag strings into human-readable timeline events.

    Args:
        flags: List of rule type strings (e.g. ["BRUTE_FORCE", "LONG_SESSION"]).

    Returns:
        List of readable event description strings. Unknown flags are skipped.
    """
    return [
        _FLAG_TIMELINE[flag]
        for flag in flags
        if flag in _FLAG_TIMELINE
    ]
