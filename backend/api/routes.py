"""
routes.py — Thin routing layer for TraceShield X++ (port 8000)

Port 8000 responsibilities:
  - Dataset sampling / synthetic log generation
  - Delegating ALL detection to port 8001 /ingest
  - Mapping IngestResponse → UI response format
  - Graph queries, status, health

Port 8000 does NOT:
  - Score, classify, or override any risk values
  - Run ML inference
  - Modify risk_score or status returned from port 8001
"""

import logging
import random
import datetime
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

INGEST_URL = "http://127.0.0.1:8001/ingest"

try:
    from backend.core.ml_model      import get_sample_row
    from backend.core.simulation    import generate_synthetic_logs, generate_attack_scenario, get_all_log_lines
    from backend.core.graph_builder import get_attack_graph, clear_graph
    from backend.core.summarizer    import generate_timeline
    from backend.core.neo4j_db      import test_connection
    from backend.core.risk          import get_risk_color
except ImportError:
    from core.ml_model      import get_sample_row
    from core.simulation    import generate_synthetic_logs, generate_attack_scenario, get_all_log_lines
    from core.graph_builder import get_attack_graph, clear_graph
    from core.summarizer    import generate_timeline
    from core.neo4j_db      import test_connection
    from core.risk          import get_risk_color

router = APIRouter()


# ── Delegation helper ─────────────────────────────────────────────────────────

def _delegate_to_ingest(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send a log row to port 8001 /ingest and map the response to UI format.
    No scoring, no overrides — values come entirely from port 8001.
    """
    ip     = row.get("src_ip") or (
        f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    )
    device = row.get("name") or row.get("protocol_type", "UNKNOWN")

    # request_count: use login_attempts as primary signal, capped at 200
    failed   = int(row.get("failed_logins", 0) or 0)
    attempts = int(row.get("login_attempts", 0) or 0)
    traffic  = int(row.get("network_traffic_volume", 0) or 0)
    request_count = min(
        max(failed * 3 + attempts * 2 + (traffic // 20000), attempts, 1),
        200,
    )

    payload = {"ip": ip, "device": device, "request_count": request_count}
    logger.info("Delegating to ingestion service: ip=%s, device=%s, count=%d",
                ip, device, request_count)

    try:
        resp = httpx.post(INGEST_URL, json=payload, timeout=10.0)
        resp.raise_for_status()
        ingest_data = resp.json()
    except httpx.ConnectError:
        logger.error("Ingestion service unreachable at %s", INGEST_URL)
        raise HTTPException(
            status_code=502,
            detail="Ingestion service (port 8001) is not reachable. Start it first.",
        )
    except httpx.HTTPStatusError as exc:
        logger.error("Ingestion service HTTP error: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))

    # ── Map IngestResponse → UI format (no value changes) ────────────────────
    status     = ingest_data.get("status", "NORMAL")
    risk_score = ingest_data.get("risk_score", 0.0)   # exact value from port 8001
    components = ingest_data.get("components", {})
    response   = ingest_data.get("response", {})
    ml_score   = components.get("ml_score", 0.0)

    # risk_level and risk_color derived from status (not from score)
    status_to_level = {
        "EXTREME_RISK": "CRITICAL",
        "HIGH_RISK":    "HIGH",
        "SUSPICIOUS":   "MEDIUM",
        "NORMAL":       "LOW",
    }
    risk_level = status_to_level.get(status, "LOW")
    risk_color = get_risk_color(risk_level)

    # anomaly: True whenever ingestion classified as non-normal
    anomaly = status != "NORMAL"

    # flags derived from row features (for UI display only — do not affect score)
    actions  = response.get("actions_taken", [])
    reason   = response.get("reason", "")
    flags    = _derive_flags(row, reason)
    readable = _readable_flags(flags)

    # summary built from ingestion result
    summary  = _build_summary(risk_level, flags, readable, row, anomaly,
                               ingest_data.get("message", ""))
    timeline = generate_timeline(flags)

    # breakdown for AlertFeed vector panel — from ingestion components
    breakdown = {
        "ml_contribution":          round(ml_score * 0.30, 2),
        "rule_contribution":        round(components.get("spike_score", 0) * 0.15, 2),
        "ip_contribution":          round(components.get("log_score", 0) * 0.15, 2),
        "brute_force_contribution": round(components.get("temporal_score", 0) * 0.20, 2),
    }

    logger.info("Ingestion result: ip=%s status=%s risk_score=%.2f",
                ip, status, risk_score)

    return {
        "risk_score":     risk_score,
        "risk_level":     risk_level,
        "risk_color":     risk_color,
        "anomaly":        anomaly,
        "anomaly_score":  round(ml_score / 100.0, 4),
        "flags":          flags,
        "readable_flags": readable,
        "features":       row,
        "summary":        summary,
        "graph_updated":  False,
        "breakdown":      breakdown,
        "timeline":       timeline,
        "status":         status,
        "components":     components,
        "response":       response,
    }


# ── Flag derivation (UI display only) ────────────────────────────────────────

def _derive_flags(row: Dict[str, Any], reason: str) -> List[str]:
    flags = []
    if row.get("failed_logins", 0) > 3 or row.get("login_attempts", 0) > 8:
        flags.append("BRUTE_FORCE")
    if row.get("ip_reputation_score", 1.0) < 0.4:
        flags.append("LOW_REPUTATION_IP")
    if row.get("unusual_time_access", 0) == 1:
        flags.append("ODD_ACCESS_TIME")
    if row.get("session_duration", 0) > 300:
        flags.append("LONG_SESSION")
    if row.get("network_traffic_volume", 0) > 50000:
        flags.append("DATA_EXFILTRATION")
    if row.get("privilege_escalation", 0) == 1 or row.get("sudo_attempt", 0) == 1:
        flags.append("PRIVILEGE_ESCALATION")
    if "spike" in reason or "trend" in reason:
        flags.append("TRAFFIC_SPIKE")
    return flags


_FLAG_READABLE = {
    "BRUTE_FORCE":          "Brute Force Attack",
    "LOW_REPUTATION_IP":    "Suspicious IP Address",
    "ODD_ACCESS_TIME":      "Unusual Access Time",
    "LONG_SESSION":         "Abnormal Session Duration",
    "DATA_EXFILTRATION":    "Possible Data Exfiltration",
    "TRAFFIC_SPIKE":        "Traffic Spike Detected",
    "PRIVILEGE_ESCALATION": "Privilege Escalation Detected",
}

def _readable_flags(flags: List[str]) -> List[str]:
    return [_FLAG_READABLE.get(f, f) for f in flags]


def _build_summary(risk_level: str, flags: List[str], readable: List[str],
                   row: Dict[str, Any], anomaly: bool, message: str) -> str:
    """Build human-readable summary from ingestion result — no score manipulation."""
    openers = {
        "CRITICAL": "CRITICAL risk detected.",
        "HIGH":     "HIGH risk activity detected.",
        "MEDIUM":   "Suspicious behavior detected.",
        "LOW":      "LOW risk. System activity appears normal.",
    }
    parts = [openers.get(risk_level, "Activity detected.")]

    if anomaly:
        parts.append("Anomalous behavior confirmed by the detection pipeline.")
    else:
        parts.append("No anomaly detected by the ML model.")

    scenario = row.get("name", "")
    if scenario:
        parts.append(f"Attack pattern: {scenario}.")
    elif readable:
        parts.append(f"Triggered rules: {', '.join(readable)}.")

    indicators = []
    if row.get("failed_logins", 0) > 3:
        indicators.append(f"{row['failed_logins']} failed login attempts")
    if row.get("network_traffic_volume", 0) > 50000:
        indicators.append(f"high traffic volume ({row['network_traffic_volume']:,} bytes)")
    if row.get("unusual_time_access", 0):
        indicators.append("off-hours access")
    if row.get("ip_reputation_score", 1.0) < 0.4:
        indicators.append(f"low-reputation IP (score {row.get('ip_reputation_score', 0):.2f})")
    if indicators:
        parts.append(f"Indicators: {'; '.join(indicators)}.")

    recs = {
        "CRITICAL": "Immediate investigation required.",
        "HIGH":     "Potential threat — monitor closely.",
        "MEDIUM":   "Suspicious activity — review recommended.",
        "LOW":      "System behavior appears normal.",
    }
    parts.append(recs.get(risk_level, ""))

    return " ".join(p for p in parts if p)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/analyze")
def analyze(request: Request) -> Dict[str, Any]:
    """Sample a row from the dataset and delegate to port 8001."""
    try:
        row = get_sample_row(request.app.state.df)
        return _delegate_to_ingest(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("/analyze error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


class SimulateRequest(BaseModel):
    count: int = 1


@router.post("/simulate")
def simulate(request: Request, body: SimulateRequest) -> List[Dict[str, Any]]:
    """Generate attack scenarios and delegate each to port 8001."""
    count = max(1, min(body.count, 50))
    try:
        logs    = [generate_attack_scenario() for _ in range(count)]
        results = [_delegate_to_ingest(log) for log in logs]
        return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error("/simulate error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/graph")
def graph() -> Dict[str, Any]:
    try:
        data = get_attack_graph()
        return {"nodes": data.get("nodes", []), "edges": data.get("edges", []),
                "count": len(data.get("nodes", []))}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/graph/clear")
def graph_clear() -> Dict[str, str]:
    try:
        clear_graph()
        return {"message": "Graph cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
def status(request: Request) -> Dict[str, Any]:
    try:
        df = request.app.state.df
        return {
            "neo4j":        test_connection(),
            "model_loaded": request.app.state.model is not None,
            "dataset_rows": len(df),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics")
def analytics(request: Request) -> Dict[str, Any]:
    """Run 50 synthetic logs through port 8001 and aggregate pattern data."""
    try:
        logs    = generate_synthetic_logs(50)
        results = [_delegate_to_ingest(log) for log in logs]

        flag_counts: Dict[str, int] = {}
        for r in results:
            for f in r.get("flags", []):
                flag_counts[f] = flag_counts.get(f, 0) + 1

        risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in results:
            lvl = r.get("risk_level", "LOW").upper()
            if lvl in risk_dist:
                risk_dist[lvl] += 1

        buckets = []
        for i in range(0, len(results), 10):
            chunk     = results[i:i+10]
            a_count   = sum(1 for r in chunk if r.get("anomaly"))
            avg_score = round(sum(r.get("anomaly_score", 0) for r in chunk) / len(chunk), 4)
            buckets.append({"bucket": i // 10, "anomalies": a_count, "avg_score": avg_score})

        proto_counts: Dict[str, int] = {}
        for log in logs:
            p = log.get("protocol_type", "UNKNOWN")
            proto_counts[p] = proto_counts.get(p, 0) + 1

        multi_flag = [
            {
                "flags":         r.get("flags", []),
                "risk_score":    r.get("risk_score", 0),
                "anomaly_score": r.get("anomaly_score", 0),
                "features": {k: r.get("features", {}).get(k) for k in [
                    "failed_logins", "login_attempts", "session_duration",
                    "ip_reputation_score", "unusual_time_access",
                    "network_traffic_volume", "protocol_type",
                ]},
            }
            for r in results if len(r.get("flags", [])) >= 2
        ][:10]

        return {
            "total_logs":    len(results),
            "anomaly_count": sum(1 for r in results if r.get("anomaly")),
            "flag_counts":   flag_counts,
            "risk_dist":     risk_dist,
            "buckets":       buckets,
            "proto_counts":  proto_counts,
            "multi_flag":    multi_flag,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threat-scan")
def threat_scan(request: Request) -> Dict[str, Any]:
    """Run 30 attack scenarios via port 8001, return structured threat report."""
    try:
        logs    = [generate_attack_scenario() for _ in range(30)]
        results = [_delegate_to_ingest(log) for log in logs]
        worst   = max(results, key=lambda r: r.get("risk_score", 0))
        features = worst.get("features", {})

        def rand_ip():
            return (f"{random.randint(10,220)}.{random.randint(1,254)}"
                    f".{random.randint(1,254)}.{random.randint(1,254)}")
        def rand_mac():
            return ":".join(f"{random.randint(0,255):02X}" for _ in range(6))

        attacker_ip       = rand_ip()
        attacker_username = random.choice(["root","admin","ubuntu","deploy","svc_backup"])
        now = datetime.datetime.utcnow()

        flag_event_map = {
            "BRUTE_FORCE": {
                "source": "auth.log",
                "description": f"Brute-force SSH — {features.get('failed_logins','?')} failed attempts from {attacker_ip}",
                "evidence": f"sshd[{random.randint(1000,9999)}]: Failed password for {attacker_username} from {attacker_ip}",
            },
            "LOW_REPUTATION_IP": {
                "source": "fail2ban.log",
                "description": f"Low-reputation IP {attacker_ip} (score {round(features.get('ip_reputation_score',0),3)})",
                "evidence": f"fail2ban.actions: Ban {attacker_ip} — score below threshold",
            },
            "ODD_ACCESS_TIME": {
                "source": "auth.log",
                "description": "Authentication at unusual hour",
                "evidence": f"pam_unix: auth failure; user={attacker_username} rhost={attacker_ip}",
            },
            "LONG_SESSION": {
                "source": "syslog",
                "description": f"Long session: {features.get('session_duration','?')}s",
                "evidence": f"systemd: Session for {attacker_username} active {features.get('session_duration','?')}s",
            },
            "DATA_EXFILTRATION": {
                "source": "netflow",
                "description": f"Large outbound transfer: {features.get('network_traffic_volume','?')} bytes",
                "evidence": f"netflow: {attacker_ip}:443 -> external — possible exfiltration",
            },
        }

        events = [{
            "time": (now - datetime.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
            "source": "kern.log",
            "description": f"Port scan from {attacker_ip} — {random.randint(200,800)} ports probed",
            "evidence": f"kernel: [UFW BLOCK] IN=eth0 SRC={attacker_ip} PROTO=TCP",
        }]
        for i, flag in enumerate(worst.get("flags", [])):
            if flag in flag_event_map:
                t = (now - datetime.timedelta(minutes=30 - i*7)).strftime("%Y-%m-%d %H:%M:%S")
                events.append({"time": t, **flag_event_map[flag]})

        flags_readable = worst.get("readable_flags", worst.get("flags", []))
        return {
            "incidentId":       f"INC-{now.strftime('%Y%m%d')}-{random.randint(100,999)}",
            "incidentDate":     now.strftime("%Y-%m-%d"),
            "incidentTime":     now.strftime("%H:%M"),
            "analystName":      "TraceShield X AutoAnalyst",
            "systemAffected":   "traceshield-node-01",
            "severity":         worst.get("risk_level", "HIGH"),
            "attackerIp":       attacker_ip,
            "attackerUsername": attacker_username,
            "attackerMac":      rand_mac(),
            "attackerOs":       random.choice(["Kali Linux 2024.1","Ubuntu 22.04 (modified)","Unknown/Spoofed"]),
            "attackerLocation": random.choice([
                "Amsterdam, NL — AS14061 DigitalOcean",
                "Frankfurt, DE — AS16276 OVH SAS",
                "Moscow, RU — AS8359 MTS PJSC",
            ]),
            "events":           events,
            "summary": (
                f"TraceShield detected a {worst.get('risk_level','HIGH')}-severity incident from {attacker_ip}. "
                f"Risk score: {worst.get('risk_score',0):.2f}/100. "
                f"Triggered: {', '.join(flags_readable) if flags_readable else 'Behavioral anomaly'}."
            ),
            "impact": (
                f"Traffic: {features.get('network_traffic_volume','N/A')} bytes. "
                f"Session: {features.get('session_duration','N/A')}s. "
                f"Protocol: {features.get('protocol_type','TCP')}."
            ),
            "recommendations": (
                f"1. Block {attacker_ip} at firewall.\n"
                f"2. Audit '{attacker_username}' account.\n"
                "3. Review /var/log/auth.log.\n4. Rotate SSH keys.\n5. File incident report."
            ),
            "riskScore":    worst.get("risk_score", 0),
            "anomalyScore": worst.get("anomaly_score", 0),
            "flags":        worst.get("flags", []),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
def health(request: Request) -> Dict[str, Any]:
    try:
        return {"status": "ok", "neo4j": test_connection(),
                "model_loaded": request.app.state.model is not None}
    except Exception:
        return {"status": "ok", "neo4j": False, "model_loaded": False}


@router.get("/dataset/logs")
def dataset_logs() -> Dict[str, Any]:
    """Return all raw log lines from the intrusion dataset."""
    lines = get_all_log_lines()
    return {"lines": lines, "count": len(lines)}
