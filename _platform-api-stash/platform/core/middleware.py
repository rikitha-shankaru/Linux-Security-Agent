"""Custom middleware"""

import time
import uuid
import structlog
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse

from platform.core.config import settings

logger = structlog.get_logger(__name__)


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Add correlation ID to requests for tracing"""

    async def dispatch(self, request: Request, call_next: Callable):
        # Get or create correlation ID
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id

        response = await call_next(request)

        # Add correlation ID to response headers
        response.headers["X-Correlation-ID"] = correlation_id

        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """Collect request metrics"""

    async def dispatch(self, request: Request, call_next: Callable):
        start_time = time.time()

        response = await call_next(request)

        # Calculate latency
        latency_ms = (time.time() - start_time) * 1000

        # Log request metrics
        logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=latency_ms,
            correlation_id=getattr(request.state, "correlation_id", None),
        )

        # Add timing header
        response.headers["X-Response-Time"] = f"{latency_ms:.2f}ms"

        return response

