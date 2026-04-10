"""
linux_log_parser.py — Robust Linux log dataset parser for TraceShield.

Handles unknown/mixed log formats: auth.log, syslog, audit.log, kern.log.
Extracts security features per-line, aggregates per-IP, feeds risk engine.

Never crashes on malformed input — all parsing is wrapped in try/except.
"""

import re
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Regex patterns ────────────────────────────────────────────────────────────

_RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

_RE_FAILED_LOGIN = re.compile(
    r'Failed password|authentication failure|Invalid user|FAILED LOGIN'
    r'|pam_unix.*auth.*failure|no such user|illegal user',
    re.IGNORECASE,
)
_RE_SUCCESS_LOGIN = re.compile(
    r'Accepted password|Accepted publickey|session opened for user'
    r'|New session|logged in',
    re.IGNORECASE,
)
_RE_SUDO = re.compile(
    r'\bsudo\b.*COMMAND=|COMMAND=.*sudo|sudo\[',
    re.IGNORECASE,
)
_RE_SUSPICIOUS = re.compile(
    r'\bnc\b[\s-]|netcat|bash\s+-i|sh\s+-i|chmod\s+777'
    r'|wget\s+https?://|curl\s+https?://'
    r'|python[23]?\s+-c|perl\s+-e|ruby\s+-e'
    r'|/dev/tcp|mkfifo|base64\s+-d'
    r'|\bnmap\b|\bhydra\b|\bmetasploit\b',
    re.IGNORECASE,
)
_RE_SENSITIVE = re.compile(
    r'/etc/passwd|/etc/shadow|/etc/sudoers|/root/\.ssh'
    r'|/var/log/auth|/proc/\d+|/sys/kernel'
    r'|/etc/crontab|/etc/cron\.',
    re.IGNORECASE,
)
_RE_PORT_SCAN = re.compile(
    r'UFW BLOCK|iptables.*DROP|port scan|SCAN detected'
    r'|SYN flood|connection refused.*repeated',
    re.IGNORECASE,
)
_RE_PRIVILEGE_ESC = re.compile(
    r'su\s*:\s*FAILED|su\s*:\s*pam_authenticate'
    r'|pkexec|polkit|CVE-\d{4}-\d+',
    re.IGNORECASE,
)

# ── Per-line feature extraction ───────────────────────────────────────────────

def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single log line into structured security features.

    Returns None only on empty input — never raises.
    IP defaults to 'unknown' if not found in line.
    """
    try:
        line = line.strip()
        if not line:
            return None

        ips = _RE_IP.findall(line)
        ip  = ips[0] if ips else "unknown"

        return {
            "ip":                   ip,
            "failed_login":         1 if _RE_FAILED_LOGIN.search(line)   else 0,
            "successful_login":     1 if _RE_SUCCESS_LOGIN.search(line)  else 0,
            "sudo_attempt":         1 if _RE_SUDO.search(line)           else 0,
            "suspicious_command":   1 if _RE_SUSPICIOUS.search(line)     else 0,
            "sensitive_file_access":1 if _RE_SENSITIVE.search(line)      else 0,
            "port_scan":            1 if _RE_PORT_SCAN.search(line)      else 0,
            "privilege_escalation": 1 if _RE_PRIVILEGE_ESC.search(line)  else 0,
            "raw":                  line,
        }
    except Exception as exc:
        logger.warning("parse_line skipped malformed input: %s", exc)
        return None


# ── Batch parsing ─────────────────────────────────────────────────────────────

def parse_lines(lines: List[str]) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Parse a list of raw log lines.

    Returns:
        (parsed_events, total_lines, valid_events)
    """
    parsed, valid = [], 0
    for line in lines:
        result = parse_line(line)
        if result:
            parsed.append(result)
            valid += 1
    logger.info("DATASET PARSE | total=%d valid=%d skipped=%d",
                len(lines), valid, len(lines) - valid)
    return parsed, len(lines), valid


# ── Per-IP aggregation ────────────────────────────────────────────────────────

def aggregate_by_ip(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Group parsed events by IP and sum security feature counts.

    Returns dict: ip → aggregated feature counts
    """
    agg: Dict[str, Dict[str, int]] = defaultdict(lambda: {
        "failed_logins":           0,
        "successful_logins":       0,
        "sudo_attempts":           0,
        "suspicious_commands":     0,
        "sensitive_file_accesses": 0,
        "port_scans":              0,
        "privilege_escalations":   0,
        "total_events":            0,
    })

    for ev in events:
        ip = ev.get("ip", "unknown")
        a  = agg[ip]
        a["failed_logins"]           += ev.get("failed_login", 0)
        a["successful_logins"]       += ev.get("successful_login", 0)
        a["sudo_attempts"]           += ev.get("sudo_attempt", 0)
        a["suspicious_commands"]     += ev.get("suspicious_command", 0)
        a["sensitive_file_accesses"] += ev.get("sensitive_file_access", 0)
        a["port_scans"]              += ev.get("port_scan", 0)
        a["privilege_escalations"]   += ev.get("privilege_escalation", 0)
        a["total_events"]            += 1

    return dict(agg)


# ── Log score from aggregated features ───────────────────────────────────────

_MAX_RAW = 300.0  # theoretical max for normalization

def score_from_features(features: Dict[str, int]) -> float:
    """
    Compute a 0–100 log_score from aggregated feature counts.

    Weights chosen to reflect severity:
        failed_logins           × 10
        sudo_attempts           × 20
        suspicious_commands     × 25
        sensitive_file_accesses × 15
        port_scans              × 15
        privilege_escalations   × 30
    """
    raw = (
        features.get("failed_logins",           0) * 10 +
        features.get("sudo_attempts",           0) * 20 +
        features.get("suspicious_commands",     0) * 25 +
        features.get("sensitive_file_accesses", 0) * 15 +
        features.get("port_scans",              0) * 15 +
        features.get("privilege_escalations",   0) * 30
    )
    return round(min(raw / _MAX_RAW * 100.0, 100.0), 2)


def classify_log_score(score: float) -> str:
    if score >= 60: return "EXTREME_RISK"
    if score >= 40: return "HIGH_RISK"
    if score >= 20: return "SUSPICIOUS"
    return "NORMAL"


def build_reason(features: Dict[str, int]) -> str:
    parts = []
    if features.get("failed_logins", 0):
        parts.append(f"failed_logins={features['failed_logins']}")
    if features.get("sudo_attempts", 0):
        parts.append(f"sudo={features['sudo_attempts']}")
    if features.get("suspicious_commands", 0):
        parts.append(f"suspicious_cmds={features['suspicious_commands']}")
    if features.get("sensitive_file_accesses", 0):
        parts.append(f"sensitive_files={features['sensitive_file_accesses']}")
    if features.get("port_scans", 0):
        parts.append(f"port_scans={features['port_scans']}")
    if features.get("privilege_escalations", 0):
        parts.append(f"priv_esc={features['privilege_escalations']}")
    return ", ".join(parts) if parts else "no_signals_detected"


# ── Full dataset analysis pipeline ───────────────────────────────────────────

def analyze_log_dataset(lines: List[str]) -> Dict[str, Any]:
    """
    Full pipeline: parse → aggregate → score → classify per IP.

    Args:
        lines: Raw log lines from any Linux log file.

    Returns:
        {
          "summary": { total_lines, valid_events, unique_ips, anomalies },
          "results": [ { ip, risk_score, status, actions, reason, features } ]
        }
    """
    events, total, valid = parse_lines(lines)
    by_ip = aggregate_by_ip(events)

    results = []
    anomaly_count = 0

    for ip, features in by_ip.items():
        score  = score_from_features(features)
        status = classify_log_score(score)
        reason = build_reason(features)

        # Derive actions from status (mirrors response_engine logic)
        actions: List[str] = []
        if status == "SUSPICIOUS":
            actions = ["flagged"]
        elif status == "HIGH_RISK":
            actions = ["redirected_to_honeypot"]
        elif status == "EXTREME_RISK":
            actions = ["blocked", "redirected_to_honeypot"]

        if status != "NORMAL":
            anomaly_count += 1

        results.append({
            "ip":         ip,
            "risk_score": score,
            "status":     status,
            "actions":    actions,
            "reason":     reason,
            "features":   features,
        })

    # Sort by risk_score descending
    results.sort(key=lambda r: r["risk_score"], reverse=True)

    logger.info(
        "DATASET ANALYSIS | lines=%d valid=%d ips=%d anomalies=%d",
        total, valid, len(by_ip), anomaly_count,
    )

    return {
        "summary": {
            "total_lines":  total,
            "valid_events": valid,
            "unique_ips":   len(by_ip),
            "anomalies":    anomaly_count,
        },
        "results": results,
    }
