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
    graph_updated = build_graph_from_detection(anomaly, row)

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


# ── Endpoint 6: Health ───────────────────────────────────────────────────────

@router.get("/health")
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
