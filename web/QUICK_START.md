# Quick Start Guide - Web Dashboard

## Problem: "I don't see anything"

If you see a blank page at `http://localhost:5000`, follow these steps:

## Step 1: Install Dependencies

```bash
cd web
pip3 install --user -r requirements.txt
```

Or if you have a virtual environment:
```bash
source venv/bin/activate  # if you have one
pip install -r requirements.txt
```

## Step 2: Start the Server

```bash
cd web
python3 app.py
```

You should see:
```
============================================================
🛡️  Linux Security Agent - Web Dashboard
============================================================

Starting web server...
Access the dashboard at: http://localhost:5000
```

## Step 3: Open Browser

Open your browser and go to: **http://localhost:5000**

## Troubleshooting

### Port 5000 already in use?
```bash
# Kill existing process
lsof -ti:5000 | xargs kill -9

# Or use a different port
# Edit app.py, change: socketio.run(app, host='0.0.0.0', port=5001)
```

### Dependencies not found?
```bash
# Check if installed
python3 -c "import flask; import flask_socketio; print('OK')"

# If error, install:
pip3 install --user Flask flask-socketio python-socketio eventlet
```

### Server not starting?
Check the error messages:
```bash
cd web
python3 app.py
```

Look for error messages and fix them.

## Quick Start Script

Use the provided script:
```bash
cd web
./start_dashboard.sh
```

This will:
1. Check dependencies
2. Install if needed
3. Kill any existing server
4. Start the dashboard

## What You Should See

1. **Landing Page** (`http://localhost:5000`):
   - Project title and description
   - Feature cards
   - "Start Monitoring" button

2. **Monitoring Page** (`http://localhost:5000/monitor`):
   - Terminal output area
   - Statistics sidebar
   - Start/Stop buttons

If you still see a blank page, check:
- Browser console for errors (F12)
- Server terminal for error messages
- Firewall blocking port 5000

