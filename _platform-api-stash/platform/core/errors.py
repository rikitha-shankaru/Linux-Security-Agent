"""
RFC 7807 Problem Details for HTTP APIs
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from fastapi import HTTPException, status


class ProblemDetail(BaseModel):
    """RFC 7807 problem detail format"""

    type: Optional[str] = Field(
        None, description="A URI reference that identifies the problem type"
    )
    title: str = Field(..., description="A short, human-readable summary")
    status: int = Field(..., description="The HTTP status code")
    detail: Optional[str] = Field(None, description="A human-readable explanation")
    instance: Optional[str] = Field(
        None, description="A URI reference that identifies the specific occurrence"
    )
    correlation_id: Optional[str] = Field(
        None, description="Correlation ID for tracing"
    )
    remediation: Optional[str] = Field(
        None, description="Suggested remediation steps"
    )
    errors: Optional[Dict[str, Any]] = Field(
        None, description="Additional error details"
    )


class ProblemHTTPException(HTTPException):
    """HTTP Exception that returns RFC 7807 format"""

    def __init__(
        self,
        status_code: int,
        title: str,
        detail: Optional[str] = None,
        instance: Optional[str] = None,
        correlation_id: Optional[str] = None,
        remediation: Optional[str] = None,
        errors: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.title = title
        self.instance = instance
        self.correlation_id = correlation_id
        self.remediation = remediation
        self.errors = errors


# Common problem types
class ErrorCodes:
    """Stable error codes for clients"""

    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    IDEMPOTENCY_KEY_REQUIRED = "idempotency_key_required"
    DUPLICATE_EVENT = "duplicate_event"
    INVALID_CURSOR = "invalid_cursor"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INTERNAL_ERROR = "internal_error"

