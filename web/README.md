# Web Dashboard for Linux Security Agent

A web-based interface for monitoring and managing the Linux Security Agent.

## Features

- **Landing Page**: Project overview and features
- **Live Monitoring Dashboard**: Real-time terminal output and statistics
- **Agent Control**: Start/stop agent from web interface
- **Real-time Updates**: WebSocket-based live log streaming
- **Visual Alerts**: Attack and anomaly detection alerts
- **Statistics**: Live stats (processes, high risk, anomalies, attacks, syscalls)

## Installation

```bash
cd web
pip install -r requirements.txt
```

## Running

```bash
python app.py
```

Then open your browser to: `http://localhost:5000`

## Usage

1. **Landing Page** (`/`): Learn about the project
2. **Monitoring Dashboard** (`/monitor`): 
   - Click "Start Agent" to begin monitoring
   - Watch real-time logs in the terminal
   - See statistics update in real-time
   - Get visual alerts for attacks and anomalies

## API Endpoints

- `GET /api/status` - Get agent status
- `POST /api/agent/start` - Start the agent
- `POST /api/agent/stop` - Stop the agent
- `GET /api/systems` - Get registered systems
- `POST /api/systems` - Register a new system

## WebSocket Events

- `log` - New log entry
- `alert` - Attack or anomaly detected
- `status` - Connection status

## Requirements

- Python 3.8+
- Flask
- flask-socketio
- Agent must be runnable with sudo (for eBPF)

## Notes

- The agent runs in headless mode when started from the web interface
- Logs are streamed in real-time via WebSocket
- Statistics are parsed from log messages
- Visual alerts appear for high-risk detections and anomalies

