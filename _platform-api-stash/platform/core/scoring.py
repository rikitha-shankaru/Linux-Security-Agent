"""Real-time risk scoring engine"""

from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional

from platform.core.database import Event, Score, Process

# Base risk scores for syscalls (similar to your agent)
SYCALL_RISK_SCORES = {
    "ptrace": 10,
    "setuid": 8,
    "setgid": 8,
    "execve": 5,
    "mount": 4,
    "chmod": 3,
    "fork": 2,
    "open": 1,
    "read": 1,
    "write": 1,
}


class ScoreCalculator:
    """Calculate risk scores for processes"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def recalculate_score(self, process_id: str) -> Optional[Score]:
        """Recalculate risk score for a process based on recent events"""
        # Get process
        process = await self.db.get(Process, process_id)
        if not process:
            return None

        # Get recent events (last 5 minutes)
        cutoff = datetime.utcnow() - timedelta(minutes=5)
        result = await self.db.execute(
            select(Event)
            .where(
                Event.process_id == process_id,
                Event.timestamp >= cutoff,
            )
            .order_by(Event.timestamp.desc())
        )
        events = result.scalars().all()

        if not events:
            return None

        # Calculate base risk score
        risk_score = 0.0
        for event in events:
            risk_score += SYCALL_RISK_SCORES.get(event.syscall, 2)

        # Normalize to 0-100 scale
        risk_score = min(100.0, risk_score / len(events) * 10)

        # Get or create score record
        score_id = f"{process_id}:{datetime.utcnow().isoformat()}"
        score = Score(
            id=score_id,
            process_id=process_id,
            agent_id=process.agent_id,
            pid=process.pid,
            risk_score=risk_score,
            calculated_at=datetime.utcnow(),
        )
        self.db.add(score)
        await self.db.flush()

        return score

    async def get_latest_score(self, process_id: str) -> Optional[Score]:
        """Get latest score for a process"""
        result = await self.db.execute(
            select(Score)
            .where(Score.process_id == process_id)
            .order_by(Score.calculated_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

