"""
main.py — FastAPI entry point for the TraceShield ingestion service.
Real-time anomaly detection with Neo4j graph storage.
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from ingestion.models.schemas import IngestPayload, IngestResponse
from ingestion.services.anomaly import process_event
from ingestion.services.ml_engine import get_model
from ingestion.db.neo4j_conn import close_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Ingestion service starting up — training ML model...")
    get_model()   # warm up: trains on 8000 synthetic samples at startup
    logger.info("ML model ready.")
    yield
    close_driver()
    logger.info("Ingestion service shut down.")


app = FastAPI(
    title="TraceShield Ingestion API",
    description="Real-time cybersecurity event ingestion and anomaly detection.",
    version="1.0.0",
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
    return {"status": "online", "service": "TraceShield Ingestion API"}


@app.post("/ingest", response_model=IngestResponse)
def ingest(payload: IngestPayload) -> IngestResponse:
    """
    Ingest a single network event and run real-time anomaly detection.

    - Logs every incoming request.
    - Flags anomaly if request_count > 100.
    - Stores anomalous events in Neo4j as graph relationships.
    """
    try:
        ts = payload.timestamp or datetime.utcnow()
        result = process_event(
            ip=payload.ip,
            device=payload.device,
            request_count=payload.request_count,
            timestamp=ts,
        )
        return IngestResponse(
            status="anomaly" if result["anomaly"] else "ok",
            anomaly=result["anomaly"],
            confidence=result["confidence"],
            message=result["message"],
            ip=payload.ip,
            device=payload.device,
            request_count=payload.request_count,
            timestamp=ts,
        )
    except Exception as exc:
        logger.error("Ingest error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
