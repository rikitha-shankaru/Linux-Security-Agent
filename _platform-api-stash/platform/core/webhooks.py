"""Webhook delivery system with exponential backoff"""

import asyncio
import httpx
import time
from typing import Dict, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, Boolean
from sqlalchemy.orm import declarative_base
import json
import structlog

from platform.core.config import settings
from platform.core.database import Base

logger = structlog.get_logger(__name__)


class WebhookDelivery(Base):
    """Webhook delivery tracking"""

    __tablename__ = "webhook_deliveries"

    id = Column(String, primary_key=True)
    url = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    payload = Column(JSON, nullable=False)
    signature = Column(String)
    status = Column(String, default="pending")  # pending, success, failed, dead_letter
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    delivered_at = Column(DateTime, nullable=True)
    next_retry_at = Column(DateTime, nullable=True)


class WebhookSender:
    """Send webhooks with retry logic"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.client = httpx.AsyncClient(timeout=settings.WEBHOOK_TIMEOUT)

    async def send(self, url: str, event_type: str, payload: dict, signature: str = None):
        """Send webhook with automatic retry"""
        delivery = WebhookDelivery(
            id=f"{event_type}:{int(time.time())}",
            url=url,
            event_type=event_type,
            payload=payload,
            signature=signature,
        )
        self.db.add(delivery)
        await self.db.flush()

        # Try delivery
        success = await self._deliver(delivery)

        if success:
            delivery.status = "success"
            delivery.delivered_at = datetime.utcnow()
        else:
            delivery.status = "failed"
            # Schedule retry
            if delivery.retry_count < settings.WEBHOOK_MAX_RETRIES:
                backoff = settings.WEBHOOK_BACKOFF_BASE ** delivery.retry_count
                delivery.next_retry_at = datetime.utcnow().replace(second=int(backoff))
            else:
                delivery.status = "dead_letter"

        await self.db.commit()

    async def _deliver(self, delivery: WebhookDelivery) -> bool:
        """Attempt webhook delivery"""
        headers = {
            "Content-Type": "application/json",
            "X-Event-Type": delivery.event_type,
            "X-Delivery-ID": delivery.id,
        }

        if delivery.signature:
            headers["X-Signature"] = delivery.signature

        try:
            response = await self.client.post(
                delivery.url,
                json=delivery.payload,
                headers=headers,
            )
            response.raise_for_status()
            logger.info(
                "webhook_delivered",
                delivery_id=delivery.id,
                url=delivery.url,
                status_code=response.status_code,
            )
            return True
        except Exception as e:
            logger.warning(
                "webhook_delivery_failed",
                delivery_id=delivery.id,
                url=delivery.url,
                error=str(e),
                retry_count=delivery.retry_count,
            )
            delivery.retry_count += 1
            return False

    async def retry_failed(self):
        """Retry failed webhooks (called by background task)"""
        from sqlalchemy import select

        # Find webhooks ready for retry
        now = datetime.utcnow()
        result = await self.db.execute(
            select(WebhookDelivery).where(
                WebhookDelivery.status == "failed",
                WebhookDelivery.retry_count < settings.WEBHOOK_MAX_RETRIES,
                WebhookDelivery.next_retry_at <= now,
            )
        )
        deliveries = result.scalars().all()

        for delivery in deliveries:
            success = await self._deliver(delivery)
            if success:
                delivery.status = "success"
                delivery.delivered_at = datetime.utcnow()
            else:
                if delivery.retry_count >= settings.WEBHOOK_MAX_RETRIES:
                    delivery.status = "dead_letter"
                else:
                    backoff = settings.WEBHOOK_BACKOFF_BASE ** delivery.retry_count
                    delivery.next_retry_at = datetime.utcnow().replace(second=int(backoff))

        await self.db.commit()


async def trigger_risk_threshold_webhook(
    db: AsyncSession,
    process_id: str,
    risk_score: float,
    threshold: float,
    webhook_url: str,
):
    """Trigger webhook when risk threshold is crossed"""
    import hmac
    import hashlib
    import base64

    payload = {
        "event_type": "risk_threshold_crossed",
        "process_id": process_id,
        "risk_score": risk_score,
        "threshold": threshold,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Sign payload
    signature = hmac.new(
        settings.HMAC_SECRET_KEY.encode(),
        json.dumps(payload).encode(),
        hashlib.sha256,
    ).digest()
    signature_b64 = base64.b64encode(signature).decode()

    sender = WebhookSender(db)
    await sender.send(webhook_url, "risk_threshold_crossed", payload, signature_b64)

