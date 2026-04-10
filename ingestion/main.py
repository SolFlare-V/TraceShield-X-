"""
main.py — FastAPI entry point for the TraceShield ingestion service.
Real-time anomaly detection with unified risk scoring and Neo4j storage.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from ingestion.models.schemas import IngestPayload, IngestResponse, ResponseDetail
from ingestion.services.anomaly_detector import process_event
from ingestion.services.ml_model import get_ml_score, load_model, reload_model, is_loaded
from ingestion.services.response_engine import get_full_state
from ingestion.services.log_parser import (
    parse_log_lines,
    ingest_logs_for_ip,
    get_ip_log_summary,
)
from ingestion.services.linux_log_parser import analyze_log_dataset
from ingestion.services.ml_training import (
    train as ml_train,
    evaluate as ml_evaluate,
)
from ingestion.db.neo4j import (
    get_all_relationships,
    get_recent_attacks,
    get_ip_history,
    get_graph_summary,
    get_attack_chain,
    close_driver as close_neo4j,
)
from ingestion.db.neo4j_conn import close_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Ingestion service starting...")
    loaded = load_model()
    if loaded:
        logger.info("ML model ready. Service online.")
    else:
        logger.warning(
            "Service starting WITHOUT ML model. "
            "Fallback scoring active. POST /ml/train to enable ML."
        )
    yield
    close_driver()
    close_neo4j()
    logger.info("Ingestion service shut down.")


app = FastAPI(
    title="TraceShield Ingestion API",
    description="Real-time cybersecurity event ingestion with unified risk scoring.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "online", "service": "TraceShield Ingestion API v2.0"}


@app.post("/ingest", response_model=IngestResponse)
async def ingest(payload: IngestPayload) -> IngestResponse:
    """
    Ingest a single network event and run real-time unified risk scoring.
    Broadcasts result to all connected WebSocket clients.
    """
    try:
        ts = payload.timestamp or datetime.now(timezone.utc).replace(tzinfo=None)
        result = process_event(
            ip=payload.ip,
            device=payload.device,
            request_count=payload.request_count,
            timestamp=ts,
        )
        response_obj = IngestResponse(
            status=result["status"],
            risk_score=result["risk_score"],
            message=result["message"],
            ip=payload.ip,
            device=payload.device,
            request_count=payload.request_count,
            timestamp=ts,
            graph_stored=result["graph_stored"],
            components=result["components"],
            response=result["response"],
        )
        # Broadcast to WebSocket clients (non-blocking)
        ws_payload = {
            "ip":           payload.ip,
            "device":       payload.device,
            "request_count": payload.request_count,
            "status":       result["status"],
            "risk_score":   result["risk_score"],
            "actions":      result["response"].get("actions_taken", []),
            "reason":       result["response"].get("reason", "N/A"),
            "log_score":    result["components"].get("log_score", 0),
            "ml_score":     result["components"].get("ml_score", 0),
            "timestamp":    ts.isoformat(),
        }
        await _ws_manager.broadcast(ws_payload)
        return response_obj
    except Exception as exc:
        logger.error("Ingest error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


import json
from typing import List as WsList

# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: WsList[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active = [c for c in self.active if c != ws]

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


_ws_manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming."""
    await _ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()   # keep alive
    except WebSocketDisconnect:
        _ws_manager.disconnect(websocket)
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


# ── Log ingestion endpoints ───────────────────────────────────────────────────

class LogIngestRequest(BaseModel):
    ip: str
    log_lines: list[str]


@app.post("/ingest/logs")
def ingest_logs(body: LogIngestRequest):
    """
    Ingest Linux system log lines for a specific IP.
    Updates per-IP log state used in hybrid risk scoring.
    """
    result = ingest_logs_for_ip(body.ip, body.log_lines)
    logger.info("LOG INGEST | ip=%s lines=%d log_score=%.2f",
                body.ip, len(body.log_lines), result["log_score"])
    return {
        "ip":         body.ip,
        "lines_parsed": len(body.log_lines),
        **result,
    }


@app.get("/logs/{ip_address}")
def get_log_summary(ip_address: str):
    """Return aggregated log signals for a specific IP."""
    return {"ip": ip_address, "log_summary": get_ip_log_summary(ip_address)}


# ── Dataset log analysis endpoint ─────────────────────────────────────────────

class DatasetLogsRequest(BaseModel):
    log_lines: list[str]


@app.post("/dataset/logs")
async def dataset_logs(body: DatasetLogsRequest):
    """
    Analyze a batch of raw Linux log lines from any log format.

    All scoring flows through the unified pipeline:
      linux_log_parser → aggregate per-IP → process_event() → broadcast WS

    Input:  { "log_lines": ["<raw log line>", ...] }
    Output: { "summary": {...}, "results": [{ip, risk_score, status, ...}] }
    """
    try:
        if not body.log_lines:
            raise HTTPException(status_code=400, detail="log_lines must not be empty")

        # Step 1: parse + aggregate per-IP using linux_log_parser
        from ingestion.services.linux_log_parser import parse_lines, aggregate_by_ip
        events, total, valid = parse_lines(body.log_lines)
        by_ip = aggregate_by_ip(events)

        logger.info(
            "DATASET/LOGS | lines=%d valid=%d unique_ips=%d",
            total, valid, len(by_ip),
        )

        results = []
        anomaly_count = 0

        for ip, features in by_ip.items():
            # Step 2: seed per-IP log state so risk_engine picks up log signals
            ingest_logs_for_ip(ip, [
                ev["raw"] for ev in events if ev.get("ip") == ip
            ])

            # Step 3: run through the unified pipeline (same as /ingest)
            ts = datetime.now(timezone.utc).replace(tzinfo=None)
            result = process_event(
                ip=ip,
                device="dataset_log",
                request_count=max(features.get("total_events", 1), 1),
                timestamp=ts,
            )

            status   = result["status"]
            score    = result["risk_score"]
            response = result["response"]

            if status != "NORMAL":
                anomaly_count += 1

            # Step 4: broadcast to WebSocket clients
            ws_payload = {
                "ip":            ip,
                "device":        "dataset_log",
                "request_count": features.get("total_events", 1),
                "status":        status,
                "risk_score":    score,
                "actions":       response.get("actions_taken", []),
                "reason":        response.get("reason", "N/A"),
                "log_score":     result["components"].get("log_score", 0),
                "ml_score":      result["components"].get("ml_score", 0),
                "timestamp":     ts.isoformat(),
            }
            # Broadcast immediately, then yield to event loop so the WS message
            # is flushed to clients before processing the next IP (live stream effect)
            await _ws_manager.broadcast(ws_payload)
            await asyncio.sleep(0.075)  # 75ms pacing between events

            results.append({
                "ip":         ip,
                "risk_score": score,
                "status":     status,
                "actions":    response.get("actions_taken", []),
                "reason":     response.get("reason", "N/A"),
                "features":   features,
                "components": result["components"],
            })

        # Sort by risk_score descending
        results.sort(key=lambda r: r["risk_score"], reverse=True)

        logger.info(
            "DATASET/LOGS DONE | ips=%d anomalies=%d",
            len(by_ip), anomaly_count,
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

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("dataset/logs error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ── ML training endpoints ─────────────────────────────────────────────────────

@app.post("/ml/train")
def ml_train_endpoint():
    """
    Train the Isolation Forest on 8 unified features and save to disk.
    Reloads model into memory immediately after training.
    """
    try:
        ml_train(csv_path=None, save=True)
        success = reload_model()
        if not success:
            raise RuntimeError("Model saved but failed to reload from disk.")
        return {
            "status":       "trained",
            "model_loaded": True,
            "features":     8,
            "feature_cols": ["request_count","requests_per_second","spike_score",
                             "trend_score","failed_logins","sudo_attempts",
                             "suspicious_commands","sensitive_file_access"],
            "message":      "Model trained on 8 unified features, saved and reloaded.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ml/status")
def ml_status():
    """Return current ML model load status."""
    return {
        "model_loaded": is_loaded(),
        "feature_count": 8,
        "feature_cols": ["request_count","requests_per_second","spike_score",
                         "trend_score","failed_logins","sudo_attempts",
                         "suspicious_commands","sensitive_file_access"],
        "message": (
            "Model loaded and ready for inference."
            if is_loaded() else
            "Model not loaded. POST /ml/train to train and load."
        ),
    }


@app.get("/ml/evaluate")
def ml_evaluate_endpoint():
    """Evaluate the trained model and return anomaly metrics."""
    try:
        result = ml_evaluate(csv_path=None)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/blocked")
def blocked_list():
    """Return full in-memory response state with timestamps and reasons."""
    return get_full_state()


@app.get("/graph")
def graph_all():
    """Fetch all Neo4j relationships for visualization."""
    return {"relationships": get_all_relationships(100)}


@app.get("/graph/attacks")
def graph_attacks():
    """Fetch recent ATTACKED relationships with metadata."""
    return {"attacks": get_recent_attacks(20)}


@app.get("/graph/ip/{ip_address}")
def graph_ip(ip_address: str):
    """Fetch all graph relationships for a specific IP."""
    return {"ip": ip_address, "history": get_ip_history(ip_address)}


@app.get("/graph/chain/{ip_address}")
def graph_chain(ip_address: str):
    """Fetch full attack chain path for an IP (IP → Device → Honeypot → System)."""
    return {"ip": ip_address, "chain": get_attack_chain(ip_address)}


@app.get("/graph/summary")
def graph_summary():
    """Return node and relationship counts."""
    return get_graph_summary()
