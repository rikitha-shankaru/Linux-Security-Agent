"""Database setup and models"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, Index
from datetime import datetime
import json

from platform.core.config import settings

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite://"),
    echo=settings.DEBUG,
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()


class Agent(Base):
    """Agent registration table"""

    __tablename__ = "agents"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    hostname = Column(String)
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    metadata = Column(JSON, default=dict)

    def __repr__(self):
        return f"<Agent(id={self.id}, name={self.name})>"


class Process(Base):
    """Process tracking table"""

    __tablename__ = "processes"

    id = Column(String, primary_key=True)  # agent_id:pid:timestamp hash
    agent_id = Column(String, nullable=False, index=True)
    pid = Column(Integer, nullable=False)
    name = Column(String)
    started_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    metadata = Column(JSON, default=dict)

    __table_args__ = (
        Index("idx_agent_pid", "agent_id", "pid"),
    )

    def __repr__(self):
        return f"<Process(id={self.id}, agent_id={self.agent_id}, pid={self.pid})>"


class Event(Base):
    """Event ingestion table"""

    __tablename__ = "events"

    id = Column(String, primary_key=True)  # idempotency key or generated
    agent_id = Column(String, nullable=False, index=True)
    process_id = Column(String, nullable=False, index=True)
    pid = Column(Integer, nullable=False)
    syscall = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    metadata = Column(JSON, default=dict)

    __table_args__ = (
        Index("idx_agent_timestamp", "agent_id", "timestamp"),
        Index("idx_process_timestamp", "process_id", "timestamp"),
    )

    def __repr__(self):
        return f"<Event(id={self.id}, agent_id={self.agent_id}, syscall={self.syscall})>"


class Score(Base):
    """Risk score table"""

    __tablename__ = "scores"

    id = Column(String, primary_key=True)
    process_id = Column(String, nullable=False, index=True)
    agent_id = Column(String, nullable=False, index=True)
    pid = Column(Integer, nullable=False)
    risk_score = Column(Float, nullable=False, index=True)
    anomaly_score = Column(Float)
    calculated_at = Column(DateTime, default=datetime.utcnow, index=True)
    metadata = Column(JSON, default=dict)

    __table_args__ = (
        Index("idx_process_risk", "process_id", "risk_score"),
        Index("idx_agent_risk", "agent_id", "risk_score"),
        Index("idx_timestamp_risk", "calculated_at", "risk_score"),
    )

    def __repr__(self):
        return f"<Score(id={self.id}, process_id={self.process_id}, risk_score={self.risk_score})>"


async def get_db() -> AsyncSession:
    """Dependency for database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

