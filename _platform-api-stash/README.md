# SysScore Platform API

A production-ready Platform API for syscall monitoring that ingests events from Linux agents, scores process behavior in real time, and exposes results to dashboards/automations.

## Features

✅ **REST API** with OpenAPI 3.0 specification  
✅ **Idempotency** - Safe retries with `Idempotency-Key` header  
✅ **Cursor-based pagination** - Stable results under concurrent writes  
✅ **RFC 7807 errors** - Standardized problem+json format  
✅ **Real-time scoring** - Risk scores calculated on event ingestion  
✅ **HMAC authentication** - Pre-shared keys for agents  
✅ **OAuth2 authentication** - For internal tools  
✅ **Webhooks** - Risk threshold notifications with retry logic  
✅ **Structured logging** - Correlation IDs for tracing  
✅ **Metrics** - Request latency and success rates  

## Architecture

```
┌─────────────────┐
│ Linux Agents    │  ← Sends events via POST /events
└────────┬────────┘
         │ HMAC-signed
         ▼
┌─────────────────┐
│ Platform API    │
│  - Event ingest │
│  - Real-time    │
│    scoring      │
│  - Webhooks     │
└────────┬────────┘
         │ REST API
         ▼
┌─────────────────┐
│ Dashboards /    │  ← Query scores via GET /scores
│ Automations     │
└─────────────────┘
```

## Quick Start

### Installation

```bash
cd platform
pip install -r requirements.txt
```

### Configuration

Create a `.env` file:

```env
DATABASE_URL=sqlite:///./sysscore.db
HMAC_SECRET_KEY=your-secret-key-here
OAUTH2_SECRET_KEY=your-oauth-secret

# Agent keys (agent_id -> secret_key)
AGENT_KEYS={"agent-1": "secret-1", "agent-2": "secret-2"}
```

### Run Server

```bash
python main.py
```

Or with uvicorn:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

API docs available at: http://localhost:8000/api/v1/docs

## API Endpoints

### Agents

- `POST /api/v1/agents` - Register agent
- `GET /api/v1/agents` - List agents
- `GET /api/v1/agents/{id}` - Get agent details

### Events

- `POST /api/v1/events` - Ingest events (with idempotency)
- `GET /api/v1/events` - List events (cursor pagination)

### Processes

- `GET /api/v1/processes` - List processes
- `GET /api/v1/processes/{id}` - Get process details

### Scores

- `GET /api/v1/scores` - Query scores (filterable, cursor pagination)
- `POST /api/v1/scores:recalculate` - Trigger recalculation

## Event Ingestion Example

```python
import requests
import hmac
import hashlib
import base64
import json

# Agent credentials
AGENT_ID = "agent-1"
SECRET_KEY = "secret-1"

# Prepare event batch
events = {
    "events": [
        {
            "pid": 1234,
            "syscall": "execve",
            "timestamp": "2025-01-15T10:00:00Z",
            "metadata": {}
        }
    ]
}

# Generate HMAC signature
payload = json.dumps(events).encode()
signature = hmac.new(
    SECRET_KEY.encode(),
    payload,
    hashlib.sha256
).digest()
signature_b64 = base64.b64encode(signature).decode()

# Send with idempotency key
headers = {
    "X-Agent-ID": AGENT_ID,
    "X-Agent-Signature": signature_b64,
    "Idempotency-Key": "unique-key-123",
    "Content-Type": "application/json"
}

response = requests.post(
    "http://localhost:8000/api/v1/events",
    json=events,
    headers=headers
)

print(response.json())
# {
#   "accepted": 1,
#   "duplicates": 0,
#   "errors": 0,
#   "results": [{"id": "...", "status": "accepted"}]
# }
```

## Query Scores Example

```python
import requests

# OAuth2 token (in production, use proper OAuth2 flow)
headers = {
    "Authorization": "Bearer your-oauth-token"
}

# Query high-risk processes
params = {
    "risk_min": 50.0,
    "limit": 100
}

response = requests.get(
    "http://localhost:8000/api/v1/scores",
    headers=headers,
    params=params
)

data = response.json()
for score in data["data"]:
    print(f"Process {score['process_id']}: Risk {score['risk_score']}")

# Pagination
cursor = data["pagination"]["cursor"]
if data["pagination"]["has_more"]:
    # Get next page
    response = requests.get(
        "http://localhost:8000/api/v1/scores",
        headers=headers,
        params={**params, "cursor": cursor}
    )
```

## Webhooks

Webhooks are triggered when risk thresholds are crossed. Configure webhook URLs in your agent registration.

Webhook payload example:
```json
{
  "event_type": "risk_threshold_crossed",
  "process_id": "agent-1:1234",
  "risk_score": 75.5,
  "threshold": 50.0,
  "timestamp": "2025-01-15T10:00:00Z"
}
```

## Error Handling

All errors follow RFC 7807 format:

```json
{
  "type": "invalid_request",
  "title": "Invalid Cursor",
  "status": 400,
  "detail": "Cursor is invalid or expired",
  "instance": "/api/v1/scores",
  "correlation_id": "abc-123",
  "remediation": "Use a valid cursor or start from beginning"
}
```

## SDKs

TypeScript and Python SDKs can be generated from the OpenAPI spec:

```bash
# Generate OpenAPI spec
curl http://localhost:8000/api/v1/openapi.json > openapi.json

# Generate Python SDK (using openapi-generator)
openapi-generator generate -i openapi.json -g python -o ./sdk/python

# Generate TypeScript SDK
openapi-generator generate -i openapi.json -g typescript-axios -o ./sdk/typescript
```

## Production Considerations

- Use PostgreSQL instead of SQLite
- Use Redis for idempotency caching
- Add rate limiting
- Enable HTTPS
- Set up proper OAuth2 provider
- Configure webhook retry queue (already implemented)
- Add monitoring/alerting (Prometheus metrics)
- Use structured logging (already implemented)

## License

MIT

