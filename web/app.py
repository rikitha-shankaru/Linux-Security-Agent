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

app = Flask(__name__, template_folder='templates', static_folder=None)
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
    
    # Check if agent is running by checking for the process
    log_file = Path(__file__).parent.parent / 'logs' / 'security_agent.log'
    agent_running = False
    agent_pid = None
    
    # Check if log file exists and is being written to (indicates agent is running)
    if log_file.exists():
        # Check if file is recent (modified in last 10 seconds)
        import time
        if time.time() - log_file.stat().st_mtime < 10:
            agent_running = True
            # Try to find the agent process
            try:
                result = subprocess.run(['pgrep', '-f', 'simple_agent.py'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout.strip():
                    agent_pid = int(result.stdout.strip().split('\n')[0])
            except:
                pass
    
    # Also check our tracked process
    if agent_process and agent_process.poll() is None:
        agent_running = True
        agent_pid = agent_process.pid
    
    status = {
        'running': agent_running,
        'monitoring': monitoring_active or agent_running,
        'pid': agent_pid
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
        log_dir = project_root / 'logs'
        log_dir.mkdir(exist_ok=True)
        
        # Try with sudo first, but handle errors gracefully
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
        
        # Wait a moment to check if process started successfully
        time.sleep(2)
        if agent_process.poll() is not None:
            # Process already exited - get error
            try:
                _, stderr_output = agent_process.communicate(timeout=1)
                error_msg = stderr_output if stderr_output else "Agent process exited immediately"
            except:
                error_msg = "Agent failed to start (check sudo permissions and eBPF support)"
            
            socketio.emit('log', {'type': 'error', 'message': f'Agent start failed: {error_msg[:200]}'})
            return jsonify({'error': f'Agent failed to start: {error_msg[:200]}'}), 500
        
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
    
    # Wait for log file to be created (longer wait for manual starts)
    max_wait = 60
    waited = 0
    while not log_file.exists() and waited < max_wait and monitoring_active:
        time.sleep(1)
        waited += 1
        if waited % 10 == 0:
            socketio.emit('log', {'type': 'info', 'message': f'Waiting for agent logs... ({waited}s) - Start agent manually if needed'})
    
    if not log_file.exists():
        socketio.emit('log', {'type': 'info', 'message': 'No log file found yet. Start the agent manually:'})
        socketio.emit('log', {'type': 'info', 'message': '  sudo python3 core/simple_agent.py --collector ebpf --threshold 20'})
        socketio.emit('log', {'type': 'info', 'message': 'Then refresh this page to see live logs'})
        # Keep monitoring in case file appears later
        while monitoring_active:
            if log_file.exists():
                break
            time.sleep(5)
        if not log_file.exists():
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
    print()
    # Get public IP if on cloud
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "localhost"
    
    print("Access options:")
    print(f"  1. Local: http://localhost:5001")
    print(f"  2. From browser SSH: http://localhost:5001 (in new tab)")
    print(f"  3. Direct (if firewall allows): http://{local_ip}:5001")
    print(f"  4. Public IP: http://136.112.137.224:5001 (if firewall rule added)")
    print()
    print("Press Ctrl+C to stop")
    print("="*60)
    print()
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=False)

