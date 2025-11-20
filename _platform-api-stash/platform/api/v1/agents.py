"""Agent management endpoints"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from platform.core.database import get_db, Agent
from fastapi import Request
from platform.core.auth import verify_oauth2_auth
from platform.core.errors import ProblemHTTPException

router = APIRouter()


class AgentCreate(BaseModel):
    """Agent registration"""

    id: str
    name: str
    hostname: Optional[str] = None
    metadata: Optional[dict] = None


class AgentResponse(BaseModel):
    """Agent response"""

    id: str
    name: str
    hostname: Optional[str]
    registered_at: datetime
    last_seen: datetime
    metadata: dict

    class Config:
        from_attributes = True


@router.post("/agents", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    agent: AgentCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(verify_oauth2_auth),
):
    """Register a new agent"""
    existing = await db.get(Agent, agent.id)
    if existing:
        raise ProblemHTTPException(
            status_code=status.HTTP_409_CONFLICT,
            title="Agent Already Exists",
            detail=f"Agent {agent.id} is already registered",
            correlation_id=getattr(request.state, "correlation_id", None),
        )

    new_agent = Agent(
        id=agent.id,
        name=agent.name,
        hostname=agent.hostname,
        metadata=agent.metadata or {},
        registered_at=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)

    return AgentResponse.model_validate(new_agent)


@router.get("/agents", response_model=List[AgentResponse])
async def list_agents(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(verify_oauth2_auth),
):
    """List all registered agents"""
    from sqlalchemy import select

    result = await db.execute(select(Agent))
    agents = result.scalars().all()
    return [AgentResponse.model_validate(agent) for agent in agents]


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(verify_oauth2_auth),
):
    """Get agent details"""
    agent = await db.get(Agent, agent_id)
    if not agent:
        raise ProblemHTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            title="Agent Not Found",
            detail=f"Agent {agent_id} not found",
            correlation_id=getattr(request.state, "correlation_id", None),
        )
    return AgentResponse.model_validate(agent)

