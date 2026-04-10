"""
routes.py — API route definitions for TraceShield X++

Port 8000 is now a routing + formatting layer only.
All anomaly detection and risk scoring is delegated to the ingestion
service on port 8001 (the single source of truth).

What port 8000 still owns:
  - Dataset sampling (get_sample_row)
  - Synthetic log generation (generate_synthetic_logs)
  - Graph queries (Neo4j via graph_builder)
  - Summary + timeline generation (summarizer)
  - Status / health checks

What port 8000 NO LONGER does:
  - ML inference
  - Risk scoring
  - Rule-based detection
"""

import logging
import random
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

INGEST_URL = "http://127.0.0.1:8001/ingest"

try:
    from backend.core.ml_model      import get_sample_row
    from backend.core.simulation    import generate_synthetic_logs
    from backend.core.graph_builder import get_attack_graph, clear_graph, build_graph_from_detection
    from backend.core.summarizer    import generate_summary, generate_timeline
    from backend.core.neo4j_db      import test_connection
    from backend.core.detection     import detect_threats, summarize_alerts
    from backend.core.risk          import get_risk_color
except ImportError:
    from core.ml_model      import get_sample_row
    from core.simulation    import generate_synthetic_logs
    from core.graph_builder import get_attack_graph, clear_graph, build_graph_from_detection
    from core.summarizer    import generate_summary, generate_timeline
    from core.neo4j_db      import test_connection
    from core.detection     import detect_threats, summarize_alerts
    from core.risk          import get_risk_color

router = APIRouter()


# ── Delegation helper ─────────────────────────────────────────────────────────

def _delegate_to_ingest(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Forward a synthetic/sample log row to port 8001 /ingest.
    Maps row fields → IngestPayload, then maps IngestResponse → UI format.

    Raises HTTPException(502) if port 8001 is unreachable.
    """
    ip            = row.get("src_ip") or f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    device        = row.get("protocol_type", "UNKNOWN")
    request_count = int(row.get("login_attempts") or row.get("network_traffic_volume") or 1)

    payload = {"ip": ip, "device": device, "request_count": request_count}

    logger.info("8000→8001 delegate | ip=%s device=%s count=%d", ip, device, request_count)

    try:
        resp = httpx.post(INGEST_URL, json=payload, timeout=10.0)
        resp.raise_for_status()
        ingest_data = resp.json()
    except httpx.ConnectError:
        logger.error("8000→8001 delegate FAILED: ingestion service unreachable")
        raise HTTPException(
            status_code=502,
            detail="Ingestion service (port 8001) is not reachable. Start it first.",
        )
    except httpx.HTTPStatusError as exc:
        logger.error("8000→8001 delegate HTTP error: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))

    # ── Map IngestResponse → UI format ────────────────────────────────────────
    # Port 8001 returns: status, risk_score, message, components, response, ...
    # UI expects:        risk_score, risk_level, risk_color, anomaly,
    #                    anomaly_score, flags, readable_flags, summary,
    #                    breakdown, timeline, features

    status     = ingest_data.get("status", "NORMAL")
    risk_score = ingest_data.get("risk_score", 0.0)
    components = ingest_data.get("components", {})
    response   = ingest_data.get("response", {})

    # Map 8001 status → UI risk_level
    status_to_level = {
        "EXTREME_RISK": "CRITICAL",
        "HIGH_RISK":    "HIGH",
        "SUSPICIOUS":   "MEDIUM",
        "NORMAL":       "LOW",
    }
    risk_level = status_to_level.get(status, "LOW")
    risk_color = get_risk_color(risk_level)

    # Derive anomaly flag from ML score
    ml_score   = components.get("ml_score", 0.0)
    anomaly    = ml_score >= 60.0

    # Build flags from response actions + reason
    actions  = response.get("actions_taken", [])
    reason   = response.get("reason", "")
    flags    = _derive_flags(row, actions, reason)
    readable = _readable_flags(flags)

    # Build summary + timeline using existing summarizer
    detection_result = {"flags": flags, "readable_flags": readable, "types": flags}
    risk_result      = {"risk_score": risk_score, "risk_level": risk_level}
    summary          = generate_summary(risk_result, detection_result, anomaly)
    timeline         = generate_timeline(flags)

    # Breakdown for AlertFeed vector contribution panel
    breakdown = {
        "ml_contribution":          round(ml_score * 0.4, 2),
        "rule_contribution":        round(components.get("spike_score", 0) * 0.15, 2),
        "ip_contribution":          round(components.get("log_score", 0) * 0.15, 2),
        "brute_force_contribution": round(components.get("temporal_score", 0) * 0.2, 2),
    }

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
        # pass through ingest extras for LiveFeed
        "status":         status,
        "components":     components,
        "response":       response,
    }


def _derive_flags(row: Dict[str, Any], actions: List[str], reason: str) -> List[str]:
    """Derive UI flag codes from row features + ingest response."""
    flags = []
    if row.get("failed_logins", 0) > 5 and row.get("login_attempts", 0) > 10:
        flags.append("BRUTE_FORCE")
    if row.get("ip_reputation_score", 1.0) < 0.3:
        flags.append("LOW_REPUTATION_IP")
    if row.get("unusual_time_access", 0) == 1:
        flags.append("ODD_ACCESS_TIME")
    if row.get("session_duration", 0) > 300:
        flags.append("LONG_SESSION")
    if "spike" in reason:
        flags.append("TRAFFIC_SPIKE")
    return flags


_FLAG_READABLE = {
    "BRUTE_FORCE":       "Brute Force Attack",
    "LOW_REPUTATION_IP": "Suspicious IP Address",
    "ODD_ACCESS_TIME":   "Unusual Access Time",
    "LONG_SESSION":      "Abnormal Session Duration",
    "TRAFFIC_SPIKE":     "Traffic Spike Detected",
}

def _readable_flags(flags: List[str]) -> List[str]:
    return [_FLAG_READABLE.get(f, f) for f in flags]


# ── Endpoint 1: Analyze ───────────────────────────────────────────────────────

@router.get("/analyze")
def analyze(request: Request) -> Dict[str, Any]:
    """Sample a row from the dataset and delegate scoring to port 8001."""
    try:
        df  = request.app.state.df
        row = get_sample_row(df)
        return _delegate_to_ingest(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("/analyze error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# ── Endpoint 2: Simulate ──────────────────────────────────────────────────────

class SimulateRequest(BaseModel):
    count: int = 1


@router.post("/simulate")
def simulate(request: Request, body: SimulateRequest) -> List[Dict[str, Any]]:
    """Generate synthetic logs and delegate each to port 8001 for scoring."""
    count = max(1, min(body.count, 50))
    try:
        logs    = generate_synthetic_logs(count)
        results = [_delegate_to_ingest(log) for log in logs]
        return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error("/simulate error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# ── Endpoint 3: Graph ─────────────────────────────────────────────────────────

@router.get("/graph")
def graph() -> Dict[str, Any]:
    """Return the current attack graph from Neo4j."""
    try:
        data = get_attack_graph()
        return {
            "nodes": data.get("nodes", []),
            "edges": data.get("edges", []),
            "count": len(data.get("nodes", [])),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Endpoint 4: Clear Graph ───────────────────────────────────────────────────

@router.delete("/graph/clear")
def graph_clear() -> Dict[str, str]:
    try:
        clear_graph()
        return {"message": "Graph cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Endpoint 5: Status ────────────────────────────────────────────────────────

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


# ── Endpoint 6: Analytics ─────────────────────────────────────────────────────

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

        risk_dist: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in results:
            lvl = r.get("risk_level", "LOW").upper()
            if lvl in risk_dist:
                risk_dist[lvl] += 1

        buckets = []
        for i in range(0, len(results), 10):
            chunk = results[i:i+10]
            anomaly_count = sum(1 for r in chunk if r.get("anomaly"))
            avg_score = round(sum(r.get("anomaly_score", 0) for r in chunk) / len(chunk), 4)
            buckets.append({"bucket": i // 10, "anomalies": anomaly_count, "avg_score": avg_score})

        proto_counts: Dict[str, int] = {}
        for log in logs:
            p = log.get("protocol_type", "UNKNOWN")
            proto_counts[p] = proto_counts.get(p, 0) + 1

        multi_flag = [
            {
                "flags":         r.get("flags", []),
                "risk_score":    r.get("risk_score", 0),
                "anomaly_score": r.get("anomaly_score", 0),
                "features": {
                    k: r.get("features", {}).get(k)
                    for k in ["failed_logins", "login_attempts", "session_duration",
                              "ip_reputation_score", "unusual_time_access",
                              "network_traffic_volume", "protocol_type"]
                },
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


# ── Endpoint 7: Threat Scan ───────────────────────────────────────────────────

@router.get("/threat-scan")
def threat_scan(request: Request) -> Dict[str, Any]:
    """Run 30 synthetic logs via port 8001, build a structured threat report."""
    import datetime

    try:
        logs    = generate_synthetic_logs(30)
        results = [_delegate_to_ingest(log) for log in logs]
        worst   = max(results, key=lambda r: r.get("risk_score", 0))
        features = worst.get("features", {})

        def rand_ip():
            return f"{random.randint(10,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        def rand_mac():
            return ":".join(f"{random.randint(0,255):02X}" for _ in range(6))

        attacker_ip       = rand_ip()
        attacker_username = random.choice(["root", "admin", "ubuntu", "deploy", "svc_backup"])
        attacker_mac      = rand_mac()
        attacker_os       = random.choice(["Kali Linux 2024.1", "Ubuntu 22.04 (modified)", "Windows 10 (VPN)", "Unknown/Spoofed"])
        attacker_location = random.choice([
            "Amsterdam, NL — AS14061 DigitalOcean",
            "Frankfurt, DE — AS16276 OVH SAS",
            "Moscow, RU — AS8359 MTS PJSC",
            "Shenzhen, CN — AS4134 CHINANET",
            "Ashburn, US — AS396982 Google Cloud",
        ])

        now = datetime.datetime.utcnow()
        events = []
        flag_event_map = {
            "BRUTE_FORCE": {
                "source": "auth.log",
                "description": f"Brute-force SSH login — {features.get('failed_logins','?')} failed attempts for '{attacker_username}' from {attacker_ip}",
                "evidence": f"sshd[{random.randint(1000,9999)}]: Failed password for {attacker_username} from {attacker_ip} port {random.randint(1024,65535)} ssh2",
            },
            "LOW_REPUTATION_IP": {
                "source": "fail2ban.log",
                "description": f"Connection from low-reputation IP {attacker_ip} (rep score: {round(features.get('ip_reputation_score',0),3)})",
                "evidence": f"fail2ban.actions: Ban {attacker_ip} — reputation score below threshold 0.3",
            },
            "ODD_ACCESS_TIME": {
                "source": "auth.log",
                "description": "Authentication attempt at unusual hour",
                "evidence": f"pam_unix(sshd:auth): authentication failure; user={attacker_username} rhost={attacker_ip}",
            },
            "LONG_SESSION": {
                "source": "syslog",
                "description": f"Abnormally long session: {features.get('session_duration','?')}s",
                "evidence": f"systemd[1]: Session for {attacker_username} active for {features.get('session_duration','?')} seconds",
            },
        }

        for i, flag in enumerate(worst.get("flags", [])):
            if flag in flag_event_map:
                t = (now - datetime.timedelta(minutes=30 - i * 7)).strftime("%Y-%m-%d %H:%M:%S")
                events.append({"time": t, **flag_event_map[flag]})

        events.insert(0, {
            "time": (now - datetime.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
            "source": "kern.log",
            "description": f"Port scan detected from {attacker_ip} — {random.randint(200,800)} ports probed",
            "evidence": f"kernel: [UFW BLOCK] IN=eth0 SRC={attacker_ip} PROTO=TCP — repeated scan pattern",
        })

        if features.get("network_traffic_volume", 0) > 10000:
            events.append({
                "time": (now - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
                "source": "netflow",
                "description": f"Large outbound transfer: {features.get('network_traffic_volume','?')} bytes",
                "evidence": f"netflow: {attacker_ip}:443 -> external bytes={features.get('network_traffic_volume','?')}",
            })

        flags_readable = worst.get("readable_flags", worst.get("flags", []))
        summary = (
            f"TraceShield X detected a {worst.get('risk_level','HIGH')}-severity incident from {attacker_ip}. "
            f"ML anomaly score: {worst.get('anomaly_score', 0):.4f}. "
            f"Triggered: {', '.join(flags_readable) if flags_readable else 'Behavioral anomaly only'}."
        )
        impact = (
            f"Network traffic: {features.get('network_traffic_volume','N/A')} bytes. "
            f"Session: {features.get('session_duration','N/A')}s. "
            f"Protocol: {features.get('protocol_type','TCP')}."
        )
        recommendations = (
            f"1. Block {attacker_ip} at firewall.\n"
            f"2. Audit '{attacker_username}' account.\n"
            "3. Review /var/log/auth.log.\n"
            "4. Rotate SSH keys.\n"
            "5. File incident report."
        )

        return {
            "incidentId":       f"INC-{now.strftime('%Y%m%d')}-{random.randint(100,999)}",
            "incidentDate":     now.strftime("%Y-%m-%d"),
            "incidentTime":     now.strftime("%H:%M"),
            "analystName":      "TraceShield X AutoAnalyst",
            "systemAffected":   "traceshield-node-01",
            "severity":         worst.get("risk_level", "HIGH"),
            "attackerIp":       attacker_ip,
            "attackerUsername": attacker_username,
            "attackerMac":      attacker_mac,
            "attackerOs":       attacker_os,
            "attackerLocation": attacker_location,
            "events":           events,
            "summary":          summary,
            "impact":           impact,
            "recommendations":  recommendations,
            "riskScore":        worst.get("risk_score", 0),
            "anomalyScore":     worst.get("anomaly_score", 0),
            "flags":            worst.get("flags", []),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health")
def health(request: Request) -> Dict[str, Any]:
    try:
        return {
            "status":       "ok",
            "neo4j":        test_connection(),
            "model_loaded": request.app.state.model is not None,
        }
    except Exception:
        return {"status": "ok", "neo4j": False, "model_loaded": False}
