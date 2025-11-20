#!/usr/bin/env python3
"""
Example: Send events from Linux agent to Platform API
"""

import requests
import hmac
import hashlib
import base64
import json
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000/api/v1/events"
AGENT_ID = "agent-1"
SECRET_KEY = "secret-key-1"  # Should match platform config


def generate_signature(payload: bytes, secret: str) -> str:
    """Generate HMAC signature"""
    signature = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).digest()
    return base64.b64encode(signature).decode()


def send_events(events: list, idempotency_key: str):
    """Send events to platform API"""
    batch = {
        "events": events
    }

    # Serialize payload
    payload = json.dumps(batch).encode()

    # Generate signature
    signature = generate_signature(payload, SECRET_KEY)

    # Headers
    headers = {
        "X-Agent-ID": AGENT_ID,
        "X-Agent-Signature": signature,
        "Idempotency-Key": idempotency_key,
        "Content-Type": "application/json"
    }

    # Send request
    response = requests.post(API_URL, json=batch, headers=headers)

    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

    return response.json()


if __name__ == "__main__":
    # Example events
    events = [
        {
            "pid": 1234,
            "syscall": "execve",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"command": "/usr/bin/ls"}
        },
        {
            "pid": 1234,
            "syscall": "open",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"path": "/etc/passwd"}
        }
    ]

    # Use a unique idempotency key
    idempotency_key = f"batch-{int(datetime.utcnow().timestamp())}"

    # Send events
    result = send_events(events, idempotency_key)

    print(f"\nAccepted: {result['accepted']}")
    print(f"Duplicates: {result['duplicates']}")
    print(f"Errors: {result['errors']}")

