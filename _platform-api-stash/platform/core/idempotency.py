"""Idempotency key handling"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from platform.core.database import Event

# Simple in-memory cache for idempotency (in production, use Redis)
_idempotency_cache = {}


async def check_idempotency(db: AsyncSession, key: str) -> Optional[str]:
    """Check if an idempotency key was already processed"""
    # Check cache first
    if key in _idempotency_cache:
        return _idempotency_cache[key]

    # Check database
    result = await db.execute(select(Event).where(Event.id == key))
    event = result.scalar_one_or_none()
    if event:
        _idempotency_cache[key] = event.id
        return event.id

    return None


async def store_idempotency(db: AsyncSession, key: str, value: str):
    """Store an idempotency key mapping"""
    _idempotency_cache[key] = value
    # In production, also store in Redis with TTL

