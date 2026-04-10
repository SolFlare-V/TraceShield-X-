"""
main.py — FastAPI entry point for the TraceShield ingestion service.
Real-time anomaly detection with unified risk scoring and Neo4j storage.
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from ingestion.models.schemas import IngestPayload, IngestResponse
from ingestion.services.anomaly_detector import process_event
from ingestion.services.ml_model import get_ml_score
from ingestion.services.response_engine import _blocked_ips, _honeypot_ips, _flagged_ips
from ingestion.db.neo4j_conn import close_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Ingestion service starting — warming up ML model...")
    # Warm up: triggers training on first call
    get_ml_score(50, datetime.now())
    logger.info("ML model ready. Service online.")
    yield
    close_driver()
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
def ingest(payload: IngestPayload) -> IngestResponse:
    """
    Ingest a single network event and run real-time unified risk scoring.

    Classification:
        0-30  → NORMAL
        30-70 → SUSPICIOUS
        70-100 → HIGH_RISK

    Stores SUSPICIOUS and HIGH_RISK events in Neo4j.
    """
    try:
        ts = payload.timestamp or datetime.now(timezone.utc).replace(tzinfo=None)
        result = process_event(
            ip=payload.ip,
            device=payload.device,
            request_count=payload.request_count,
            timestamp=ts,
        )
        return IngestResponse(
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
    except Exception as exc:
        logger.error("Ingest error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/blocked")
def blocked_list():
    """Return current in-memory blocked/flagged/honeypot state."""
    return {
        "blocked_ips":   list(_blocked_ips),
        "honeypot_ips":  list(_honeypot_ips),
        "flagged_ips":   dict(_flagged_ips),
    }
