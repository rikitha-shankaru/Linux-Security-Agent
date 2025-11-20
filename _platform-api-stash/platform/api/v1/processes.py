"""Process management endpoints"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from platform.core.database import get_db, Process
from fastapi import Request
from platform.core.auth import verify_oauth2_auth
from platform.core.errors import ProblemHTTPException

router = APIRouter()


class ProcessResponse(BaseModel):
    """Process response"""

    id: str
    agent_id: str
    pid: int
    name: Optional[str]
    started_at: datetime
    last_seen: datetime
    metadata: dict

    class Config:
        from_attributes = True


@router.get("/processes", response_model=List[ProcessResponse])
async def list_processes(
    request: Request,
    agent_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(verify_oauth2_auth),
):
    """List processes, optionally filtered by agent"""
    query = select(Process)
    if agent_id:
        query = query.where(Process.agent_id == agent_id)

    result = await db.execute(query)
    processes = result.scalars().all()
    return [ProcessResponse.model_validate(p) for p in processes]


@router.get("/processes/{process_id}", response_model=ProcessResponse)
async def get_process(
    process_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(verify_oauth2_auth),
):
    """Get process details"""
    process = await db.get(Process, process_id)
    if not process:
        raise ProblemHTTPException(
            status_code=404,
            title="Process Not Found",
            detail=f"Process {process_id} not found",
            correlation_id=getattr(request.state, "correlation_id", None),
        )
    return ProcessResponse.model_validate(process)

