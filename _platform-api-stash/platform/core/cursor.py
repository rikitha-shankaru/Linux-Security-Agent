"""Cursor-based pagination"""

import base64
import json
from datetime import datetime, timedelta
from typing import Dict, Any


def encode_cursor(data: Dict[str, Any]) -> str:
    """Encode cursor data into opaque token"""
    # Add expiry (e.g., 1 hour)
    data["expires_at"] = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    payload = json.dumps(data).encode()
    return base64.urlsafe_b64encode(payload).decode()


def decode_cursor(cursor: str) -> Dict[str, Any]:
    """Decode cursor token and validate expiry"""
    try:
        payload = base64.urlsafe_b64decode(cursor.encode())
        data = json.loads(payload)

        # Check expiry
        if "expires_at" in data:
            expires = datetime.fromisoformat(data["expires_at"])
            if datetime.utcnow() > expires:
                raise ValueError("Cursor expired")

        return data
    except Exception as e:
        raise ValueError(f"Invalid cursor: {e}")

