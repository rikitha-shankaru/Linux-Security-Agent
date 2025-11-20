# Integration Guide: Agent → Platform API

This guide shows how to integrate your Linux security agent with the SysScore Platform API.

## Overview

Your agent (`core/enhanced_security_agent.py`) currently outputs events locally. To send events to the platform:

1. **Install platform** (see `platform/README.md`)
2. **Configure agent** to send events to platform API
3. **Update agent** to include HMAC signing

## Step 1: Update Agent to Send Events

Add this to your agent's event processing:

```python
# In core/enhanced_security_agent.py

import requests
import hmac
import hashlib
import base64
import json
from datetime import datetime
from collections import deque

class PlatformClient:
    """Client for sending events to Platform API"""
    
    def __init__(self, api_url: str, agent_id: str, secret_key: str):
        self.api_url = api_url
        self.agent_id = agent_id
        self.secret_key = secret_key
        self.event_buffer = deque(maxlen=100)  # Buffer for batching
        
    def _sign_payload(self, payload: bytes) -> str:
        """Generate HMAC signature"""
        signature = hmac.new(
            self.secret_key.encode(),
            payload,
            hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode()
    
    def queue_event(self, pid: int, syscall: str, metadata: dict = None):
        """Queue an event for batch sending"""
        self.event_buffer.append({
            "pid": pid,
            "syscall": syscall,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        })
        
        # Send batch when buffer is full
        if len(self.event_buffer) >= 50:
            self.flush()
    
    def flush(self):
        """Send buffered events to platform"""
        if not self.event_buffer:
            return
            
        batch = {
            "events": list(self.event_buffer)
        }
        
        payload = json.dumps(batch).encode()
        signature = self._sign_payload(payload)
        
        headers = {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Signature": signature,
            "Idempotency-Key": f"{self.agent_id}-{int(datetime.utcnow().timestamp())}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/events",
                json=batch,
                headers=headers,
                timeout=5
            )
            response.raise_for_status()
            self.event_buffer.clear()
            self.logger.info("events_sent", count=len(batch["events"]))
        except Exception as e:
            self.logger.error("event_send_failed", error=str(e))
```

## Step 2: Integrate into Agent

In `enhanced_security_agent.py`, add platform client:

```python
# In __init__:
platform_config = self.config.get('platform', {})
if platform_config.get('enabled'):
    self.platform_client = PlatformClient(
        api_url=platform_config['api_url'],
        agent_id=platform_config['agent_id'],
        secret_key=platform_config['secret_key']
    )
else:
    self.platform_client = None

# In process_syscall_event:
if self.platform_client:
    self.platform_client.queue_event(
        pid=pid,
        syscall=syscall,
        metadata={
            "risk_score": process.get('risk_score', 0),
            "anomaly_score": process.get('anomaly_score', 0)
        }
    )
```

## Step 3: Configuration

Add to `config/config.yml`:

```yaml
platform:
  enabled: true
  api_url: "http://localhost:8000/api/v1"
  agent_id: "agent-1"
  secret_key: "secret-key-1"  # Must match platform AGENT_KEYS config
```

## Step 4: Platform Configuration

Ensure platform has your agent registered:

```python
# In platform/.env
AGENT_KEYS={"agent-1": "secret-key-1"}
```

## Benefits

✅ **Centralized monitoring** - All agents send to one platform  
✅ **Historical data** - Events stored in database  
✅ **Dashboard integration** - Query scores via API  
✅ **Webhooks** - Get alerts when risk thresholds crossed  
✅ **Idempotency** - Safe retries, no duplicate events  

## Next Steps

1. Run platform: `cd platform && python main.py`
2. Update agent config with platform settings
3. Restart agent - events will flow to platform
4. Query scores: `GET /api/v1/scores?risk_min=50`

See `platform/examples/` for more integration examples!

