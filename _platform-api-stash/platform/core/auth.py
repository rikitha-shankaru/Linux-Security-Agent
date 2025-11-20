"""Authentication and authorization"""

import hmac
import hashlib
import base64
from typing import Optional
from fastapi import Header, HTTPException, status, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from platform.core.config import settings
from platform.core.errors import ProblemHTTPException, ErrorCodes

security = HTTPBearer()


def verify_hmac_signature(
    payload: bytes, signature: str, secret_key: str
) -> bool:
    """Verify HMAC signature"""
    expected = hmac.new(
        secret_key.encode(), payload, hashlib.sha256
    ).digest()
    expected_b64 = base64.b64encode(expected).decode()
    return hmac.compare_digest(expected_b64, signature)


async def verify_agent_auth(
    request: Request,
    agent_id: str = Header(..., alias="X-Agent-ID"),
    signature: str = Header(..., alias="X-Agent-Signature"),
) -> str:
    """Verify HMAC authentication for agents"""
    if agent_id not in settings.AGENT_KEYS:
        raise ProblemHTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            title="Unauthorized",
            detail=f"Unknown agent ID: {agent_id}",
            correlation_id=getattr(request.state, "correlation_id", None),
            remediation="Register the agent or check agent_id",
        )

    secret_key = settings.AGENT_KEYS[agent_id]

    # Get request body for signature verification
    body = await request.body()
    if not verify_hmac_signature(body, signature, secret_key):
        raise ProblemHTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            title="Unauthorized",
            detail="Invalid signature",
            correlation_id=getattr(request.state, "correlation_id", None),
            remediation="Check your secret key and signature generation",
        )

    return agent_id


async def verify_oauth2_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """Verify OAuth2 token for internal tools"""
    # Simplified OAuth2 verification
    # In production, validate JWT token, check expiry, etc.
    try:
        from jose import jwt

        token = credentials.credentials
        payload = jwt.decode(
            token,
            settings.OAUTH2_SECRET_KEY,
            algorithms=[settings.OAUTH2_ALGORITHM],
        )
        return payload
    except Exception as e:
        raise ProblemHTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            title="Unauthorized",
            detail="Invalid or expired token",
            correlation_id=getattr(request.state, "correlation_id", None),
            remediation="Obtain a valid OAuth2 token",
        )

