"""
Event ingestion endpoint with idempotency support
"""

import hashlib
import json
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, Request, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import structlog

from platform.core.database import get_db, Event, Process
from platform.core.auth import verify_agent_auth, verify_oauth2_auth
from fastapi import Request
from platform.core.errors import ProblemHTTPException, ProblemDetail, ErrorCodes
from platform.core.idempotency import check_idempotency, store_idempotency
from platform.core.scoring import ScoreCalculator
from platform.core.cursor import encode_cursor, decode_cursor

logger = structlog.get_logger(__name__)

router = APIRouter()


class EventItem(BaseModel):
    """Single event item"""

    pid: int = Field(..., description="Process ID")
    syscall: str = Field(..., description="System call name")
    timestamp: Optional[datetime] = Field(None, description="Event timestamp (defaults to now)")
    metadata: Optional[dict] = Field(default_factory=dict, description="Additional metadata")


class EventBatch(BaseModel):
    """Batch of events to ingest"""

    events: List[EventItem] = Field(..., description="List of events")
    idempotency_key: Optional[str] = Field(
        None,
        description="Idempotency key for deduplication (required for retries)",
    )


class EventResponse(BaseModel):
    """Response for individual event"""

    id: str
    status: str  # "accepted" or "duplicate"
    error: Optional[str] = None


class BatchResponse(BaseModel):
    """Response for batch ingestion"""

    accepted: int = Field(..., description="Number of accepted events")
    duplicates: int = Field(..., description="Number of duplicate events")
    errors: int = Field(..., description="Number of errors")
    results: List[EventResponse] = Field(..., description="Per-event status")


@router.post("/events", response_model=BatchResponse, status_code=status.HTTP_207_MULTI_STATUS)
async def ingest_events(
    batch: EventBatch,
    request: Request,
    agent_id: str = Depends(verify_agent_auth),
    db: AsyncSession = Depends(get_db),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    """
    Ingest events from agents with idempotency support.

    - Accepts partial batches with per-item status
    - Uses Idempotency-Key header for deduplication
    - Returns 207 Multi-Status with per-item results
    """
    # Use header idempotency key if provided, otherwise from body
    key = idempotency_key or batch.idempotency_key

    if not key:
        raise ProblemHTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            title="Idempotency Key Required",
            detail="Idempotency-Key header or idempotency_key in body is required",
            correlation_id=getattr(request.state, "correlation_id", None),
            remediation="Include Idempotency-Key header for safe retries",
        )

    # Check if entire batch was already processed
    batch_key = f"batch:{key}"
    existing = await check_idempotency(db, batch_key)
    if existing:
        logger.info("duplicate_batch", idempotency_key=key, agent_id=agent_id)
        # Return the same response as before
        # In production, you'd store the original response
        return BatchResponse(
            accepted=0,
            duplicates=len(batch.events),
            errors=0,
            results=[
                EventResponse(id=existing, status="duplicate")
                for _ in batch.events
            ],
        )

    # Process events individually
    results = []
    accepted_count = 0
    duplicate_count = 0
    error_count = 0

    score_calculator = ScoreCalculator(db)

    for event_item in batch.events:
        try:
            # Create event ID from idempotency key + event data
            event_id_hash = hashlib.sha256(
                f"{key}:{event_item.pid}:{event_item.syscall}:{event_item.timestamp}".encode()
            ).hexdigest()[:32]

            # Check if event already exists
            existing_event = await check_idempotency(db, event_id_hash)
            if existing_event:
                results.append(EventResponse(id=existing_event, status="duplicate"))
                duplicate_count += 1
                continue

            # Ensure process exists
            process_id = f"{agent_id}:{event_item.pid}"
            process = await db.get(Process, process_id)
            if not process:
                process = Process(
                    id=process_id,
                    agent_id=agent_id,
                    pid=event_item.pid,
                    name=f"pid-{event_item.pid}",
                )
                db.add(process)
                await db.flush()

            # Create event
            event = Event(
                id=event_id_hash,
                agent_id=agent_id,
                process_id=process_id,
                pid=event_item.pid,
                syscall=event_item.syscall,
                timestamp=event_item.timestamp or datetime.utcnow(),
                metadata=event_item.metadata,
            )
            db.add(event)

            # Store idempotency
            await store_idempotency(db, event_id_hash, event_id_hash)

            # Trigger scoring (async - could be background task)
            await score_calculator.recalculate_score(process_id)

            results.append(EventResponse(id=event_id_hash, status="accepted"))
            accepted_count += 1

        except Exception as e:
            logger.exception("event_processing_error", event=event_item, error=str(e))
            error_count += 1
            results.append(
                EventResponse(
                    id="", status="error", error=str(e)
                )
            )

    await db.commit()

    # Store batch idempotency
    await store_idempotency(db, batch_key, batch_key)

    return BatchResponse(
        accepted=accepted_count,
        duplicates=duplicate_count,
        errors=error_count,
        results=results,
    )


@router.get("/events")
async def list_events(
    request: Request,
    agent_id: Optional[str] = None,
    process_id: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(verify_oauth2_auth),  # Internal tools only
):
    """
    List events with cursor-based pagination.

    - Filter by agent_id, process_id, time windows
    - Uses opaque, time-bounded cursors to avoid duplicates
    """
    if limit > 1000:
        limit = 1000

    query = select(Event)

    # Apply filters
    if agent_id:
        query = query.where(Event.agent_id == agent_id)
    if process_id:
        query = query.where(Event.process_id == process_id)

    # Decode cursor if provided
    if cursor:
        try:
            decoded = decode_cursor(cursor)
            if "timestamp" in decoded:
                query = query.where(Event.timestamp > decoded["timestamp"])
        except Exception:
            raise ProblemHTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                title="Invalid Cursor",
                detail="Cursor is invalid or expired",
                correlation_id=getattr(request.state, "correlation_id", None),
            )

    # Order and limit
    query = query.order_by(Event.timestamp.desc()).limit(limit + 1)

    result = await db.execute(query)
    events = result.scalars().all()

    # Check if there are more results
    has_more = len(events) > limit
    if has_more:
        events = events[:-1]

    # Generate next cursor
    next_cursor = None
    if has_more and events:
        last_event = events[-1]
        next_cursor = encode_cursor({"timestamp": last_event.timestamp.isoformat()})

    return {
        "data": [
            {
                "id": e.id,
                "agent_id": e.agent_id,
                "process_id": e.process_id,
                "pid": e.pid,
                "syscall": e.syscall,
                "timestamp": e.timestamp.isoformat(),
                "metadata": e.metadata,
            }
            for e in events
        ],
        "pagination": {
            "cursor": next_cursor,
            "has_more": has_more,
        },
    }

