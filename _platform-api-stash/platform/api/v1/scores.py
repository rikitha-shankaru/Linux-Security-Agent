"""Score query endpoints"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from platform.core.database import get_db, Score
from fastapi import Request
from platform.core.auth import verify_oauth2_auth
from platform.core.cursor import encode_cursor, decode_cursor
from platform.core.errors import ProblemHTTPException

router = APIRouter()


class ScoreResponse(BaseModel):
    """Score response"""

    id: str
    process_id: str
    agent_id: str
    pid: int
    risk_score: float
    anomaly_score: Optional[float]
    calculated_at: datetime
    metadata: dict

    class Config:
        from_attributes = True


@router.get("/scores", response_model=dict)
async def list_scores(
    request: Request,
    process_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    risk_min: Optional[float] = Query(None, ge=0, le=100),
    risk_max: Optional[float] = Query(None, ge=0, le=100),
    cursor: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(verify_oauth2_auth),
):
    """
    List scores with filtering and cursor-based pagination.

    - Filter by process_id, agent_id, risk range
    - Uses cursor pagination for stable results under concurrent writes
    """
    if limit > 1000:
        limit = 1000

    query = select(Score)

    # Apply filters
    if process_id:
        query = query.where(Score.process_id == process_id)
    if agent_id:
        query = query.where(Score.agent_id == agent_id)
    if risk_min is not None:
        query = query.where(Score.risk_score >= risk_min)
    if risk_max is not None:
        query = query.where(Score.risk_score <= risk_max)

    # Decode cursor if provided
    if cursor:
        try:
            decoded = decode_cursor(cursor)
            if "calculated_at" in decoded:
                query = query.where(Score.calculated_at > decoded["calculated_at"])
        except Exception:
            raise ProblemHTTPException(
                status_code=400,
                title="Invalid Cursor",
                detail="Cursor is invalid or expired",
                correlation_id=getattr(request.state, "correlation_id", None),
            )

    # Order and limit
    query = query.order_by(Score.calculated_at.desc()).limit(limit + 1)

    result = await db.execute(query)
    scores = result.scalars().all()

    # Check if there are more results
    has_more = len(scores) > limit
    if has_more:
        scores = scores[:-1]

    # Generate next cursor
    next_cursor = None
    if has_more and scores:
        last_score = scores[-1]
        next_cursor = encode_cursor({"calculated_at": last_score.calculated_at.isoformat()})

    return {
        "data": [ScoreResponse.model_validate(s) for s in scores],
        "pagination": {
            "cursor": next_cursor,
            "has_more": has_more,
        },
    }


@router.post("/scores:recalculate")
async def recalculate_score(
    process_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(verify_oauth2_auth),
):
    """Trigger score recalculation for a process"""
    from platform.core.scoring import ScoreCalculator

    calculator = ScoreCalculator(db)
    score = await calculator.recalculate_score(process_id)

    if not score:
        raise ProblemHTTPException(
            status_code=404,
            title="Process Not Found",
            detail=f"Process {process_id} not found",
            correlation_id=getattr(request.state, "correlation_id", None),
        )

    await db.commit()
    return ScoreResponse.model_validate(score)

