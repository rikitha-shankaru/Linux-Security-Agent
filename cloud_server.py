#!/usr/bin/env python3
"""
Simple Cloud Backend Server for Linux Security Agent
Provides REST API for agent management and data collection
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading
import os

app = Flask(__name__)
CORS(app)

class CloudBackendServer:
    """Simple cloud backend server for testing"""
    
    def __init__(self, db_path: str = "security_agent_cloud.db"):
        self.db_path = db_path
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Agents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT,
                os_type TEXT,
                os_version TEXT,
                ip_address TEXT,
                last_seen REAL,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                agent_id TEXT,
                timestamp REAL,
                event_type TEXT,
                severity TEXT,
                process_pid INTEGER,
                process_name TEXT,
                risk_score REAL,
                threat_technique TEXT,
                description TEXT,
                raw_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
            )
        ''')
        
        # Configurations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configurations (
                agent_id TEXT PRIMARY KEY,
                config_data TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def register_agent(self, agent_data: Dict) -> bool:
        """Register a new agent"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO agents 
                (agent_id, hostname, os_type, os_version, ip_address, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                agent_data['agent_id'],
                agent_data['hostname'],
                agent_data['os_type'],
                agent_data['os_version'],
                agent_data['ip_address'],
                agent_data['last_seen'],
                agent_data['status']
            ))
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"Error registering agent: {e}")
            return False
        finally:
            conn.close()
    
    def update_heartbeat(self, agent_id: str, agent_data: Dict) -> bool:
        """Update agent heartbeat"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE agents 
                SET last_seen = ?, status = ?
                WHERE agent_id = ?
            ''', (agent_data['last_seen'], agent_data['status'], agent_id))
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"Error updating heartbeat: {e}")
            return False
        finally:
            conn.close()
    
    def store_events(self, events: List[Dict]) -> bool:
        """Store security events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            for event in events:
                cursor.execute('''
                    INSERT INTO events 
                    (event_id, agent_id, timestamp, event_type, severity, 
                     process_pid, process_name, risk_score, threat_technique, 
                     description, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event['event_id'],
                    event['agent_id'],
                    event['timestamp'],
                    event['event_type'],
                    event['severity'],
                    event['process_pid'],
                    event['process_name'],
                    event['risk_score'],
                    event['threat_technique'],
                    event['description'],
                    json.dumps(event['raw_data'])
                ))
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"Error storing events: {e}")
            return False
        finally:
            conn.close()
    
    def get_agent_config(self, agent_id: str) -> Optional[Dict]:
        """Get agent configuration"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT config_data FROM configurations WHERE agent_id = ?', (agent_id,))
            result = cursor.fetchone()
            
            if result:
                return json.loads(result[0])
            return None
            
        except Exception as e:
            print(f"Error getting config: {e}")
            return None
        finally:
            conn.close()
    
    def update_agent_config(self, agent_id: str, config: Dict) -> bool:
        """Update agent configuration"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO configurations 
                (agent_id, config_data, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (agent_id, json.dumps(config)))
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"Error updating config: {e}")
            return False
        finally:
            conn.close()
    
    def get_events(self, agent_id: str = None, limit: int = 100) -> List[Dict]:
        """Get security events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if agent_id:
                cursor.execute('''
                    SELECT * FROM events 
                    WHERE agent_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (agent_id, limit))
            else:
                cursor.execute('''
                    SELECT * FROM events 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            
            events = []
            for row in cursor.fetchall():
                events.append({
                    'event_id': row[0],
                    'agent_id': row[1],
                    'timestamp': row[2],
                    'event_type': row[3],
                    'severity': row[4],
                    'process_pid': row[5],
                    'process_name': row[6],
                    'risk_score': row[7],
                    'threat_technique': row[8],
                    'description': row[9],
                    'raw_data': json.loads(row[10]) if row[10] else {},
                    'created_at': row[11]
                })
            
            return events
            
        except Exception as e:
            print(f"Error getting events: {e}")
            return []
        finally:
            conn.close()
    
    def get_agents(self) -> List[Dict]:
        """Get all agents"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM agents ORDER BY last_seen DESC')
            
            agents = []
            for row in cursor.fetchall():
                agents.append({
                    'agent_id': row[0],
                    'hostname': row[1],
                    'os_type': row[2],
                    'os_version': row[3],
                    'ip_address': row[4],
                    'last_seen': row[5],
                    'status': row[6],
                    'created_at': row[7]
                })
            
            return agents
            
        except Exception as e:
            print(f"Error getting agents: {e}")
            return []
        finally:
            conn.close()

# Initialize server
server = CloudBackendServer()

# API Routes

@app.route('/api/v1/agents/register', methods=['POST'])
def register_agent():
    """Register a new agent"""
    try:
        agent_data = request.json
        
        if server.register_agent(agent_data):
            return jsonify({'status': 'success', 'message': 'Agent registered'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Registration failed'}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/v1/agents/<agent_id>/heartbeat', methods=['POST'])
def heartbeat(agent_id):
    """Update agent heartbeat"""
    try:
        agent_data = request.json
        
        if server.update_heartbeat(agent_id, agent_data):
            return jsonify({'status': 'success', 'message': 'Heartbeat updated'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Heartbeat failed'}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/v1/events/batch', methods=['POST'])
def store_events():
    """Store security events"""
    try:
        data = request.json
        events = data.get('events', [])
        
        if server.store_events(events):
            return jsonify({'status': 'success', 'message': f'Stored {len(events)} events'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Failed to store events'}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/v1/agents/<agent_id>/config', methods=['GET'])
def get_config(agent_id):
    """Get agent configuration"""
    try:
        config = server.get_agent_config(agent_id)
        
        if config:
            return jsonify({'status': 'success', 'config': config}), 200
        else:
            return jsonify({'status': 'success', 'config': {}}), 200
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/v1/agents/<agent_id>/config', methods=['POST'])
def update_config(agent_id):
    """Update agent configuration"""
    try:
        config = request.json
        
        if server.update_agent_config(agent_id, config):
            return jsonify({'status': 'success', 'message': 'Config updated'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Failed to update config'}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/v1/agents/<agent_id>/status', methods=['POST'])
def update_status(agent_id):
    """Update agent status"""
    try:
        status = request.json
        
        # Store status update (could be extended to store in database)
        print(f"Agent {agent_id} status update: {status}")
        
        return jsonify({'status': 'success', 'message': 'Status updated'}), 200
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Dashboard routes

@app.route('/api/v1/dashboard/agents', methods=['GET'])
def dashboard_agents():
    """Get agents for dashboard"""
    try:
        agents = server.get_agents()
        return jsonify({'status': 'success', 'agents': agents}), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/v1/dashboard/events', methods=['GET'])
def dashboard_events():
    """Get recent events for dashboard"""
    try:
        limit = request.args.get('limit', 100, type=int)
        agent_id = request.args.get('agent_id')
        
        events = server.get_events(agent_id, limit)
        return jsonify({'status': 'success', 'events': events}), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/v1/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        agents = server.get_agents()
        events = server.get_events(limit=1000)
        
        # Calculate stats
        total_agents = len(agents)
        online_agents = len([a for a in agents if a['status'] == 'online'])
        
        total_events = len(events)
        critical_events = len([e for e in events if e['severity'] == 'critical'])
        high_events = len([e for e in events if e['severity'] == 'high'])
        
        stats = {
            'total_agents': total_agents,
            'online_agents': online_agents,
            'offline_agents': total_agents - online_agents,
            'total_events': total_events,
            'critical_events': critical_events,
            'high_events': high_events,
            'medium_events': len([e for e in events if e['severity'] == 'medium']),
            'low_events': len([e for e in events if e['severity'] == 'low'])
        }
        
        return jsonify({'status': 'success', 'stats': stats}), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Health check
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': time.time()}), 200

if __name__ == '__main__':
    print("🌐 Starting Cloud Backend Server...")
    print("📊 Dashboard available at: http://localhost:5000/api/v1/dashboard/stats")
    print("🔗 API endpoints available at: http://localhost:5000/api/v1/")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
