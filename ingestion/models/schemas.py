"""
schemas.py — Pydantic models for the ingestion API.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class IngestPayload(BaseModel):
    ip: str = Field(..., description="Source IP address")
    device: str = Field(..., description="Device identifier")
    request_count: int = Field(..., ge=0, description="Number of requests observed")
    timestamp: Optional[datetime] = Field(
        default_factory=datetime.utcnow,
        description="Event timestamp (UTC). Defaults to now if omitted.",
    )


class IngestResponse(BaseModel):
    status: str
    anomaly: bool
    message: str
    ip: str
    device: str
    request_count: int
    timestamp: datetime
