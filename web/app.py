#!/usr/bin/env python3
"""
Web Dashboard for Linux Security Agent
Flask backend with WebSocket support for real-time monitoring
"""

import os
import sys
import json
import subprocess
import threading
import time
import signal
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import sqlite3

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'security-agent-dashboard-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
agent_process = None
agent_thread = None
monitoring_active = False
registered_systems = {}
log_buffer = []

# Database setup
DB_PATH = Path(__file__).parent / 'dashboard.db'

def init_db():
    """Initialize SQLite database for system registration"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            hostname TEXT NOT NULL,
            ip_address TEXT,
            description TEXT,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP,
            status TEXT DEFAULT 'offline'
        )
    ''')
    conn.commit()
    conn.close()

def get_systems():
    """Get all registered systems"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM systems ORDER BY registered_at DESC')
    systems = []
    for row in c.fetchall():
        systems.append({
            'id': row[0],
            'name': row[1],
            'hostname': row[2],
            'ip_address': row[3],
            'description': row[4],
            'registered_at': row[5],
            'last_seen': row[6],
            'status': row[7]
        })
    conn.close()
    return systems

def add_system(name, hostname, ip_address=None, description=None):
    """Register a new system"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO systems (name, hostname, ip_address, description)
        VALUES (?, ?, ?, ?)
    ''', (name, hostname, ip_address, description))
    conn.commit()
    system_id = c.lastrowid
    conn.close()
    return system_id

# Initialize database
init_db()

@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@app.route('/monitor')
def monitor():
    """Monitoring dashboard"""
    return render_template('monitor.html')

@app.route('/api/status')
def api_status():
    """Get agent status"""
    global agent_process, monitoring_active
    
    status = {
        'running': agent_process is not None and agent_process.poll() is None,
        'monitoring': monitoring_active,
        'pid': agent_process.pid if agent_process and agent_process.poll() is None else None
    }
    return jsonify(status)

@app.route('/api/systems', methods=['GET'])
def api_get_systems():
    """Get all registered systems"""
    systems = get_systems()
    return jsonify(systems)

@app.route('/api/systems', methods=['POST'])
def api_register_system():
    """Register a new system"""
    data = request.json
    system_id = add_system(
        name=data.get('name'),
        hostname=data.get('hostname'),
        ip_address=data.get('ip_address'),
        description=data.get('description')
    )
    return jsonify({'id': system_id, 'message': 'System registered successfully'})

@app.route('/api/agent/start', methods=['POST'])
def api_start_agent():
    """Start the security agent"""
    global agent_process, monitoring_active
    
    if agent_process and agent_process.poll() is None:
        return jsonify({'error': 'Agent already running'}), 400
    
    try:
        # Start agent in headless mode
        project_root = Path(__file__).parent.parent
        agent_cmd = [
            'sudo', 'python3', 
            str(project_root / 'core' / 'simple_agent.py'),
            '--collector', 'ebpf',
            '--threshold', '20',
            '--headless'
        ]
        
        agent_process = subprocess.Popen(
            agent_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(project_root)
        )
        
        monitoring_active = True
        
        # Start log monitoring thread
        threading.Thread(target=monitor_agent_logs, daemon=True).start()
        
        return jsonify({'message': 'Agent started successfully', 'pid': agent_process.pid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/agent/stop', methods=['POST'])
def api_stop_agent():
    """Stop the security agent"""
    global agent_process, monitoring_active
    
    if not agent_process:
        return jsonify({'error': 'Agent not running'}), 400
    
    try:
        # Kill agent process
        agent_process.terminate()
        try:
            agent_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            agent_process.kill()
        
        # Also kill any remaining processes
        subprocess.run(['sudo', 'pkill', '-9', '-f', 'simple_agent.py'], 
                      capture_output=True)
        
        agent_process = None
        monitoring_active = False
        
        return jsonify({'message': 'Agent stopped successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def monitor_agent_logs():
    """Monitor agent log file and emit updates via WebSocket"""
    global monitoring_active, log_buffer
    
    log_file = Path(__file__).parent.parent / 'logs' / 'security_agent.log'
    
    # Wait for log file to be created
    max_wait = 30
    waited = 0
    while not log_file.exists() and waited < max_wait and monitoring_active:
        time.sleep(1)
        waited += 1
    
    if not log_file.exists():
        socketio.emit('log', {'type': 'error', 'message': 'Log file not found'})
        return
    
    # Read log file line by line
    with open(log_file, 'r') as f:
        # Go to end of file
        f.seek(0, 2)
        
        while monitoring_active:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    # Parse log line
                    log_entry = parse_log_line(line)
                    log_buffer.append(log_entry)
                    
                    # Keep buffer size manageable
                    if len(log_buffer) > 1000:
                        log_buffer = log_buffer[-500:]
                    
                    # Emit to all connected clients
                    socketio.emit('log', log_entry)
                    
                    # Check for attacks/anomalies
                    if is_attack_or_anomaly(line):
                        socketio.emit('alert', {
                            'type': 'attack' if 'HIGH RISK' in line else 'anomaly',
                            'message': line,
                            'timestamp': datetime.now().isoformat()
                        })
            else:
                time.sleep(0.5)  # Wait for new lines

def parse_log_line(line):
    """Parse log line into structured format"""
    entry = {
        'type': 'info',
        'message': line,
        'timestamp': datetime.now().isoformat()
    }
    
    # Detect log level
    if 'ERROR' in line or '❌' in line:
        entry['type'] = 'error'
    elif 'WARNING' in line or '⚠️' in line:
        entry['type'] = 'warning'
    elif 'HIGH RISK' in line or '🔴' in line:
        entry['type'] = 'attack'
    elif 'ANOMALY DETECTED' in line:
        entry['type'] = 'anomaly'
    elif 'INFO' in line or 'ℹ️' in line:
        entry['type'] = 'info'
    elif 'SCORE UPDATE' in line:
        entry['type'] = 'score'
    
    return entry

def is_attack_or_anomaly(line):
    """Check if log line indicates attack or anomaly"""
    attack_indicators = ['HIGH RISK DETECTED', '🔴', 'ANOMALY DETECTED', '⚠️']
    return any(indicator in line for indicator in attack_indicators)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', {'message': 'Connected to security agent dashboard'})
    
    # Send recent log buffer
    if log_buffer:
        for entry in log_buffer[-100:]:  # Last 100 entries
            emit('log', entry)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    pass

if __name__ == '__main__':
    print("="*60)
    print("🛡️  Linux Security Agent - Web Dashboard")
    print("="*60)
    print()
    print("Starting web server...")
    print("Access the dashboard at: http://localhost:5000")
    print()
    print("Press Ctrl+C to stop")
    print("="*60)
    print()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

