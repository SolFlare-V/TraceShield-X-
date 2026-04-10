"""
routes.py — API route definitions for TraceShield X++
Wires together all core modules into REST endpoints.
"""

from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

try:
    from backend.core.ml_model      import predict_anomaly, get_sample_row
    from backend.core.detection     import detect_threats, summarize_alerts
    from backend.core.risk          import calculate_risk, get_risk_color
    from backend.core.simulation    import generate_synthetic_logs
    from backend.core.graph_builder import (
        build_graph_from_detection,
        get_attack_graph,
        clear_graph,
    )
    from backend.core.summarizer    import generate_summary, generate_timeline
    from backend.core.neo4j_db      import test_connection
except ImportError:
    from core.ml_model      import predict_anomaly, get_sample_row
    from core.detection     import detect_threats, summarize_alerts
    from core.risk          import calculate_risk, get_risk_color
    from core.simulation    import generate_synthetic_logs
    from core.graph_builder import (
        build_graph_from_detection,
        get_attack_graph,
        clear_graph,
    )
    from core.summarizer    import generate_summary, generate_timeline
    from core.neo4j_db      import test_connection

router = APIRouter()


def _run_pipeline(request: Request, row: Dict[str, Any]) -> Dict[str, Any]:
    """Run the full analysis pipeline on a single log row."""
    model  = request.app.state.model
    scaler = request.app.state.scaler

    # ML prediction
    ml_result    = predict_anomaly(model, scaler, row)
    anomaly      = ml_result["anomaly"]
    anomaly_score = ml_result["score"]

    # Rule-based detection
    alerts           = detect_threats(row)
    detection_result = summarize_alerts(alerts)

    # Risk scoring
    risk_result = calculate_risk(anomaly_score, detection_result, row, anomaly)

    # Graph update
    flags_list = detection_result.get("types", [])
    graph_updated = build_graph_from_detection(anomaly, row, flags_list)

    # Summary
    summary  = generate_summary(risk_result, detection_result, anomaly)
    timeline = generate_timeline(detection_result.get("flags", []))

    return {
        "risk_score":    risk_result["risk_score"],
        "risk_level":    risk_result["risk_level"],
        "risk_color":    get_risk_color(risk_result["risk_level"]),
        "anomaly":       anomaly,
        "anomaly_score": round(anomaly_score, 4),
        "flags":         detection_result.get("types", []),
        "readable_flags": detection_result.get("readable_flags", []),
        "features":      row,
        "summary":       summary,
        "graph_updated": graph_updated,
        "breakdown":     risk_result["breakdown"],
        "timeline":      timeline,
    }


# ── Endpoint 1: Analyze ──────────────────────────────────────────────────────

@router.get("/analyze")
def analyze(request: Request) -> Dict[str, Any]:
    """Analyze a random sample row from the training dataset."""
    try:
        df  = request.app.state.df
        row = get_sample_row(df)
        return _run_pipeline(request, row)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Endpoint 2: Simulate ─────────────────────────────────────────────────────

class SimulateRequest(BaseModel):
    count: int = 1


@router.post("/simulate")
def simulate(request: Request, body: SimulateRequest) -> List[Dict[str, Any]]:
    """Generate synthetic logs and run the full pipeline on each."""
    count = max(1, min(body.count, 50))
    try:
        logs    = generate_synthetic_logs(count)
        results = [_run_pipeline(request, log) for log in logs]
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Endpoint 3: Graph ────────────────────────────────────────────────────────

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


# ── Endpoint 4: Clear Graph ──────────────────────────────────────────────────

@router.delete("/graph/clear")
def graph_clear() -> Dict[str, str]:
    """Delete all nodes and relationships from Neo4j."""
    try:
        clear_graph()
        return {"message": "Graph cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Endpoint 5: Status ───────────────────────────────────────────────────────

@router.get("/status")
def status(request: Request) -> Dict[str, Any]:
    """Return system health and model status."""
    try:
        df = request.app.state.df
        return {
            "neo4j":        test_connection(),
            "model_loaded": request.app.state.model is not None,
            "dataset_rows": len(df),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Endpoint 7: Analytics ────────────────────────────────────────────────────

@router.get("/analytics")
def analytics(request: Request) -> Dict[str, Any]:
    """
    Run 50 synthetic logs through the full pipeline and return
    aggregated pattern data for the analytics page Layer 3.
    """
    try:
        logs = generate_synthetic_logs(50)
        results = [_run_pipeline(request, log) for log in logs]

        # Pattern frequency — how often each flag fires
        flag_counts: Dict[str, int] = {}
        for r in results:
            for f in r.get("flags", []):
                flag_counts[f] = flag_counts.get(f, 0) + 1

        # Risk level distribution
        risk_dist: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in results:
            lvl = r.get("risk_level", "LOW").upper()
            if lvl in risk_dist:
                risk_dist[lvl] += 1

        # Anomaly rate over time (buckets of 10)
        buckets = []
        for i in range(0, len(results), 10):
            chunk = results[i:i+10]
            anomaly_count = sum(1 for r in chunk if r.get("anomaly"))
            avg_score = round(sum(r.get("anomaly_score", 0) for r in chunk) / len(chunk), 4)
            buckets.append({"bucket": i // 10, "anomalies": anomaly_count, "avg_score": avg_score})

        # Protocol breakdown from raw logs
        proto_counts: Dict[str, int] = {}
        for log in logs:
            p = log.get("protocol_type", "UNKNOWN")
            proto_counts[p] = proto_counts.get(p, 0) + 1

        # Top unusual patterns: events with 2+ flags
        multi_flag = [
            {
                "flags": r.get("flags", []),
                "risk_score": r.get("risk_score", 0),
                "anomaly_score": r.get("anomaly_score", 0),
                "features": {
                    k: r.get("features", {}).get(k)
                    for k in ["failed_logins", "login_attempts", "session_duration",
                              "ip_reputation_score", "unusual_time_access",
                              "network_traffic_volume", "protocol_type"]
                }
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/threat-scan")
def threat_scan(request: Request) -> Dict[str, Any]:
    """
    Run 30 synthetic logs, identify the most suspicious session,
    and return a fully structured threat report payload.
    """
    import random, datetime

    try:
        logs = generate_synthetic_logs(30)
        results = [_run_pipeline(request, log) for log in logs]

        # Pick the highest-risk result
        worst = max(results, key=lambda r: r.get("risk_score", 0))
        features = worst.get("features", {})

        # Derive attacker fields from features
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

        # Build event timeline from flags + features
        now = datetime.datetime.utcnow()
        events = []
        flag_event_map = {
            "BRUTE_FORCE": {
                "source": "auth.log",
                "description": f"Brute-force SSH login — {features.get('failed_logins', '?')} failed attempts for '{attacker_username}' from {attacker_ip}",
                "evidence": f"sshd[{random.randint(1000,9999)}]: Failed password for {attacker_username} from {attacker_ip} port {random.randint(1024,65535)} ssh2 (attempt {features.get('failed_logins','?')})",
            },
            "LOW_REPUTATION_IP": {
                "source": "fail2ban.log",
                "description": f"Connection from low-reputation IP {attacker_ip} (rep score: {round(features.get('ip_reputation_score',0),3)})",
                "evidence": f"fail2ban.actions: Ban {attacker_ip} — reputation score {round(features.get('ip_reputation_score',0),3)} below threshold 0.3",
            },
            "ODD_ACCESS_TIME": {
                "source": "auth.log",
                "description": f"Authentication attempt at unusual hour (off-hours access detected)",
                "evidence": f"pam_unix(sshd:auth): authentication failure; user={attacker_username} rhost={attacker_ip} — timestamp outside business hours",
            },
            "LONG_SESSION": {
                "source": "syslog",
                "description": f"Abnormally long session duration: {features.get('session_duration','?')}s (threshold: 300s)",
                "evidence": f"systemd[1]: Session for {attacker_username} active for {features.get('session_duration','?')} seconds — possible persistence",
            },
        }

        for i, flag in enumerate(worst.get("flags", [])):
            if flag in flag_event_map:
                t = (now - datetime.timedelta(minutes=30 - i * 7)).strftime("%Y-%m-%d %H:%M:%S")
                events.append({"time": t, **flag_event_map[flag]})

        # Always add initial recon event
        events.insert(0, {
            "time": (now - datetime.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
            "source": "kern.log",
            "description": f"Port scan detected from {attacker_ip} — {random.randint(200,800)} ports probed",
            "evidence": f"kernel: [UFW BLOCK] IN=eth0 SRC={attacker_ip} PROTO=TCP DPT={random.randint(22,8443)} — repeated scan pattern",
        })

        # Add exfil event if high traffic
        if features.get("network_traffic_volume", 0) > 10000:
            events.append({
                "time": (now - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
                "source": "netflow",
                "description": f"Large outbound transfer: {features.get('network_traffic_volume','?')} bytes to {attacker_ip}",
                "evidence": f"netflow: {attacker_ip}:443 -> external bytes={features.get('network_traffic_volume','?')} — possible data exfiltration",
            })

        # Build summary
        flags_readable = worst.get("readable_flags", worst.get("flags", []))
        summary = (
            f"TraceShield X detected a {worst.get('risk_level','HIGH')}-severity security incident originating from IP {attacker_ip}. "
            f"The attacker account '{attacker_username}' was identified through correlation of {len(events)} suspicious events across multiple log sources. "
            f"ML anomaly score: {worst.get('anomaly_score', 0):.4f}. "
            f"Triggered detection rules: {', '.join(flags_readable) if flags_readable else 'Behavioral anomaly only'}. "
            f"The attack chain began with port reconnaissance, escalated to credential brute-forcing, and exhibited signs of {'data exfiltration' if features.get('network_traffic_volume',0) > 10000 else 'lateral movement'}."
        )

        impact = (
            f"System '{request.app.state.df.columns[0] if hasattr(request.app.state, 'df') else 'traceshield-node-01'}' was targeted. "
            f"Network traffic volume reached {features.get('network_traffic_volume', 'N/A')} bytes. "
            f"Session duration of {features.get('session_duration', 'N/A')}s suggests {'prolonged unauthorized access' if (features.get('session_duration') or 0) > 300 else 'brief intrusion attempt'}. "
            f"Protocol used: {features.get('protocol_type', 'TCP')}. "
            f"{'Potential data exfiltration detected — sensitive data may be compromised.' if features.get('network_traffic_volume',0) > 10000 else 'No confirmed data exfiltration, but access to sensitive files cannot be ruled out.'}"
        )

        recommendations = (
            "1. Immediately block IP " + attacker_ip + " at the firewall level.\n"
            "2. Disable and audit the '" + attacker_username + "' account — reset all credentials.\n"
            "3. Enable fail2ban with stricter thresholds (max 3 attempts before ban).\n"
            "4. Review /var/log/auth.log and /var/log/audit/audit.log for the full session.\n"
            "5. Rotate all SSH keys and enforce key-only authentication.\n"
            "6. Deploy network segmentation to limit lateral movement.\n"
            "7. Preserve all logs as forensic evidence before any system changes.\n"
            "8. File an incident report with your CISO and legal team."
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
def health(request: Request) -> Dict[str, Any]:
    """Lightweight health check for uptime monitoring."""
    try:
        return {
            "status":       "ok",
            "neo4j":        test_connection(),
            "model_loaded": request.app.state.model is not None,
        }
    except Exception:
        return {"status": "ok", "neo4j": False, "model_loaded": False}
