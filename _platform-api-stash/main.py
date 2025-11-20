"""
SysScore Platform API - Main Entry Point

A production-ready Platform API for syscall monitoring that:
- Ingests events from Linux agents
- Scores process behavior in real time
- Exposes results via REST API
- Supports dashboards and automations
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog
from contextlib import asynccontextmanager

from platform.api.v1 import agents, processes, events, scores
from platform.core.config import settings
from platform.core.errors import ProblemDetail, ProblemHTTPException
from platform.core.middleware import CorrelationMiddleware, MetricsMiddleware
from platform.core.database import init_db

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    logger.info("initializing_database")
    await init_db()
    yield
    # Shutdown
    logger.info("shutting_down")


app = FastAPI(
    title="SysScore Platform API",
    description="Risk-scoring Platform API for syscall-monitoring agents",
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom middleware
app.add_middleware(CorrelationMiddleware)
app.add_middleware(MetricsMiddleware)


# Include routers
app.include_router(agents.router, prefix="/api/v1", tags=["agents"])
app.include_router(processes.router, prefix="/api/v1", tags=["processes"])
app.include_router(events.router, prefix="/api/v1", tags=["events"])
app.include_router(scores.router, prefix="/api/v1", tags=["scores"])


@app.exception_handler(ProblemHTTPException)
async def problem_exception_handler(request: Request, exc: ProblemHTTPException):
    """Handle ProblemHTTPException with RFC 7807 format"""
    problem = ProblemDetail(
        status=exc.status_code,
        title=exc.title,
        detail=exc.detail,
        instance=str(request.url),
        correlation_id=exc.correlation_id or getattr(request.state, "correlation_id", None),
        remediation=exc.remediation,
        errors=exc.errors,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=problem.model_dump(exclude_none=True),
        headers={"Content-Type": "application/problem+json"},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler returning RFC 7807 format"""
    logger.exception("unhandled_exception", path=request.url.path)
    problem = ProblemDetail(
        status=500,
        title="Internal Server Error",
        detail="An unexpected error occurred",
        instance=str(request.url),
        correlation_id=getattr(request.state, "correlation_id", None),
    )
    return JSONResponse(
        status_code=500,
        content=problem.model_dump(exclude_none=True),
        headers={"Content-Type": "application/problem+json"},
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "SysScore Platform API",
        "version": "1.0.0",
        "docs": "/api/v1/docs",
        "openapi": "/api/v1/openapi.json",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_config=None,  # Use structlog
    )

