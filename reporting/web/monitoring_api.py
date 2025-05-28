# shikra/reporting/web/monitoring_api.py
# API endpoints for real-time monitoring functionality

import os
import sys
import json
import logging
import time
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from pathlib import Path
import threading
import queue
import psutil
import random

# Add parent directories to path for Shikra imports
sys.path.append(str(Path(__file__).parents[3]))

logger = logging.getLogger(__name__)

# Create Blueprint
monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/api/v1/monitoring')

# Global monitoring state
class MonitoringState:
    def __init__(self):
        self.is_active = False
        self.is_paused = False
        self.start_time = None
        self.event_queue = queue.Queue()
        self.subscribers = set()  # WebSocket connections
        self.metrics = {
            'total_events': 0,
            'events_per_second': 0.0,
            'suspicious_events': 0,
            'processes': 0,
            'connections': 0,
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_io': 0.0,
            'network_io': 0.0
        }
        self.processes = {}
        self.connections = {}
        self.activities = []
        self.monitor_thread = None
        self.last_event_time = time.time()

monitoring_state = MonitoringState()

# Helper functions
def generate_event_id():
    """Generate unique event ID"""
    return f"evt_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"

def get_system_metrics():
    """Get current system metrics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk_io = psutil.disk_io_counters()
        network_io = psutil.net_io_counters()
        
        return {
            'cpu_usage': cpu_percent,
            'memory_usage': memory.percent,
            'disk_io': (disk_io.read_bytes + disk_io.write_bytes) / (1024 * 1024),  # MB
            'network_io': (network_io.bytes_sent + network_io.bytes_recv) / (1024 * 1024)  # MB
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_io': 0.0,
            'network_io': 0.0
        }

def simulate_monitoring_data():
    """Simulate monitoring data for demonstration"""
    event_types = [
        {
            'category': 'process',
            'subcategory': 'creation',
            'severities': ['info', 'low', 'medium'],
            'titles': [
                'Process created: {}',
                'Child process spawned: {}',
                'Service started: {}'
            ],
            'processes': ['cmd.exe', 'powershell.exe', 'notepad.exe', 'explorer.exe', 'svchost.exe']
        },
        {
            'category': 'file',
            'subcategory': 'write',
            'severities': ['info', 'medium', 'high'],
            'titles': [
                'File modified: {}',
                'File created: {}',
                'File deleted: {}'
            ],
            'files': [
                'C:\\Windows\\Temp\\temp.tmp',
                'C:\\Users\\Admin\\Documents\\document.txt',
                'C:\\Program Files\\App\\config.ini'
            ]
        },
        {
            'category': 'registry',
            'subcategory': 'modification',
            'severities': ['medium', 'high'],
            'titles': [
                'Registry key modified: {}',
                'Registry value created: {}',
                'Persistence mechanism: {}'
            ],
            'keys': [
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKLM\\System\\CurrentControlSet\\Services',
                'HKCU\\Software\\Classes'
            ]
        },
        {
            'category': 'network',
            'subcategory': 'connection',
            'severities': ['info', 'medium', 'high'],
            'titles': [
                'Network connection: {}',
                'DNS query: {}',
                'HTTP request: {}'
            ],
            'destinations': [
                '8.8.8.8:53',
                'google.com:443',
                'suspicious-domain.com:80',
                '192.168.1.100:4444'
            ]
        }
    ]
    
    event_type = random.choice(event_types)
    severity = random.choice(event_type['severities'])
    title_template = random.choice(event_type['titles'])
    
    if event_type['category'] == 'process':
        target = random.choice(event_type['processes'])
        details = {
            'process': target,
            'pid': str(random.randint(1000, 9999)),
            'command': f'{target} {random.choice(["/c", "-Command", ""])} {random.choice(["dir", "whoami", "netstat"])}'
        }
    elif event_type['category'] == 'file':
        target = random.choice(event_type['files'])
        details = {
            'path': target,
            'process': random.choice(['explorer.exe', 'notepad.exe', 'cmd.exe']),
            'pid': str(random.randint(1000, 9999))
        }
    elif event_type['category'] == 'registry':
        target = random.choice(event_type['keys'])
        details = {
            'key': target,
            'value': 'malware.exe',
            'process': random.choice(['malware.exe', 'setup.exe', 'installer.exe']),
            'pid': str(random.randint(1000, 9999))
        }
    else:  # network
        target = random.choice(event_type['destinations'])
        details = {
            'destination': target,
            'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
            'process': random.choice(['chrome.exe', 'firefox.exe', 'malware.exe']),
            'pid': str(random.randint(1000, 9999))
        }
    
    return {
        'id': generate_event_id(),
        'timestamp': time.time(),
        'category': event_type['category'],
        'subcategory': event_type['subcategory'],
        'severity': severity,
        'title': title_template.format(target),
        'description': f"{event_type['category'].title()} activity detected",
        'process': details.get('process', 'Unknown'),
        'pid': details.get('pid', ''),
        'details': details
    }

def monitoring_worker():
    """Background thread for generating monitoring events"""
    while monitoring_state.is_active:
        if not monitoring_state.is_paused:
            try:
                # Generate simulated event
                event = simulate_monitoring_data()
                
                # Add to activities list
                monitoring_state.activities.insert(0, event)
                
                # Limit activities list size
                if len(monitoring_state.activities) > 1000:
                    monitoring_state.activities = monitoring_state.activities[:1000]
                
                # Update metrics
                monitoring_state.metrics['total_events'] += 1
                if event['severity'] in ['high', 'critical']:
                    monitoring_state.metrics['suspicious_events'] += 1
                
                # Track processes and connections
                if event['category'] == 'process':
                    monitoring_state.processes[event['pid']] = {
                        'pid': event['pid'],
                        'name': event['process'],
                        'command': event['details'].get('command', ''),
                        'timestamp': event['timestamp'],
                        'suspicious': event['severity'] in ['high', 'critical']
                    }
                    monitoring_state.metrics['processes'] = len(monitoring_state.processes)
                
                elif event['category'] == 'network':
                    conn_id = f"{event['pid']}_{event['details']['destination']}"
                    monitoring_state.connections[conn_id] = {
                        'id': conn_id,
                        'destination': event['details']['destination'],
                        'protocol': event['details']['protocol'],
                        'process': event['process'],
                        'pid': event['pid'],
                        'timestamp': event['timestamp'],
                        'suspicious': event['severity'] in ['high', 'critical']
                    }
                    monitoring_state.metrics['connections'] = len(monitoring_state.connections)
                
                # Update system metrics
                sys_metrics = get_system_metrics()
                monitoring_state.metrics.update(sys_metrics)
                
                # Calculate events per second
                current_time = time.time()
                time_diff = current_time - monitoring_state.last_event_time
                monitoring_state.metrics['events_per_second'] = 1.0 / time_diff if time_diff > 0 else 0.0
                monitoring_state.last_event_time = current_time
                
                # Add to event queue for real-time updates
                monitoring_state.event_queue.put({
                    'type': 'monitoring_update',
                    'event_type': 'activity',
                    'data': event
                })
                
                # Send process updates
                if event['category'] == 'process':
                    monitoring_state.event_queue.put({
                        'type': 'monitoring_update',
                        'event_type': 'process',
                        'data': monitoring_state.processes[event['pid']]
                    })
                
                # Send network updates
                elif event['category'] == 'network':
                    monitoring_state.event_queue.put({
                        'type': 'monitoring_update',
                        'event_type': 'network',
                        'data': monitoring_state.connections[conn_id]
                    })
                
                # Send metrics update every 10 events
                if monitoring_state.metrics['total_events'] % 10 == 0:
                    monitoring_state.event_queue.put({
                        'type': 'monitoring_update',
                        'event_type': 'metrics',
                        'data': monitoring_state.metrics
                    })
                
            except Exception as e:
                logger.error(f"Error in monitoring worker: {e}")
        
        # Sleep between events (adjust for event frequency)
        sleep_time = random.uniform(0.5, 3.0)  # Random interval between 0.5-3 seconds
        time.sleep(sleep_time)

# API Routes
@monitoring_bp.route('/status', methods=['GET'])
def get_monitoring_status():
    """Get current monitoring status"""
    return jsonify({
        'success': True,
        'data': {
            'is_active': monitoring_state.is_active,
            'is_paused': monitoring_state.is_paused,
            'start_time': monitoring_state.start_time.isoformat() if monitoring_state.start_time else None,
            'uptime': (datetime.now() - monitoring_state.start_time).total_seconds() if monitoring_state.start_time else 0,
            'metrics': monitoring_state.metrics
        }
    })

@monitoring_bp.route('/start', methods=['POST'])
def start_monitoring():
    """Start monitoring"""
    if monitoring_state.is_active:
        return jsonify({
            'success': False,
            'error': 'Monitoring is already active'
        }), 400
    
    monitoring_state.is_active = True
    monitoring_state.is_paused = False
    monitoring_state.start_time = datetime.now()
    
    # Reset metrics
    monitoring_state.metrics = {
        'total_events': 0,
        'events_per_second': 0.0,
        'suspicious_events': 0,
        'processes': 0,
        'connections': 0,
        'cpu_usage': 0.0,
        'memory_usage': 0.0,
        'disk_io': 0.0,
        'network_io': 0.0
    }
    
    # Clear previous data
    monitoring_state.activities.clear()
    monitoring_state.processes.clear()
    monitoring_state.connections.clear()
    
    # Start monitoring thread
    monitoring_state.monitor_thread = threading.Thread(target=monitoring_worker, daemon=True)
    monitoring_state.monitor_thread.start()
    
    logger.info("Monitoring started")
    return jsonify({'success': True, 'message': 'Monitoring started'})

@monitoring_bp.route('/stop', methods=['POST'])
def stop_monitoring():
    """Stop monitoring"""
    if not monitoring_state.is_active:
        return jsonify({
            'success': False,
            'error': 'Monitoring is not active'
        }), 400
    
    monitoring_state.is_active = False
    monitoring_state.is_paused = False
    
    logger.info("Monitoring stopped")
    return jsonify({'success': True, 'message': 'Monitoring stopped'})

@monitoring_bp.route('/pause', methods=['POST'])
def pause_monitoring():
    """Pause/resume monitoring"""
    if not monitoring_state.is_active:
        return jsonify({
            'success': False,
            'error': 'Monitoring is not active'
        }), 400
    
    monitoring_state.is_paused = not monitoring_state.is_paused
    action = 'paused' if monitoring_state.is_paused else 'resumed'
    
    logger.info(f"Monitoring {action}")
    return jsonify({'success': True, 'message': f'Monitoring {action}'})

@monitoring_bp.route('/reset', methods=['POST'])
def reset_monitoring():
    """Reset monitoring data"""
    # Clear all data
    monitoring_state.activities.clear()
    monitoring_state.processes.clear()
    monitoring_state.connections.clear()
    
    # Reset metrics
    monitoring_state.metrics = {
        'total_events': 0,
        'events_per_second': 0.0,
        'suspicious_events': 0,
        'processes': 0,
        'connections': 0,
        'cpu_usage': 0.0,
        'memory_usage': 0.0,
        'disk_io': 0.0,
        'network_io': 0.0
    }
    
    logger.info("Monitoring data reset")
    return jsonify({'success': True, 'message': 'Monitoring data reset'})

@monitoring_bp.route('/activities', methods=['GET'])
def get_activities():
    """Get recent activities"""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    category = request.args.get('category')
    severity = request.args.get('severity')
    
    # Filter activities
    filtered_activities = monitoring_state.activities
    
    if category:
        filtered_activities = [a for a in filtered_activities if a['category'] == category]
    
    if severity:
        filtered_activities = [a for a in filtered_activities if a['severity'] == severity]
    
    # Apply pagination
    total = len(filtered_activities)
    activities = filtered_activities[offset:offset + limit]
    
    return jsonify({
        'success': True,
        'data': activities,
        'total': total,
        'limit': limit,
        'offset': offset
    })

@monitoring_bp.route('/processes', methods=['GET'])
def get_processes():
    """Get current processes"""
    return jsonify({
        'success': True,
        'data': list(monitoring_state.processes.values()),
        'total': len(monitoring_state.processes)
    })

@monitoring_bp.route('/connections', methods=['GET'])
def get_connections():
    """Get current network connections"""
    return jsonify({
        'success': True,
        'data': list(monitoring_state.connections.values()),
        'total': len(monitoring_state.connections)
    })

@monitoring_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """Get current metrics"""
    return jsonify({
        'success': True,
        'data': monitoring_state.metrics
    })

@monitoring_bp.route('/export', methods=['GET'])
def export_monitoring_data():
    """Export monitoring data"""
    export_format = request.args.get('format', 'json')
    
    data = {
        'timestamp': datetime.now().isoformat(),
        'monitoring_session': {
            'start_time': monitoring_state.start_time.isoformat() if monitoring_state.start_time else None,
            'is_active': monitoring_state.is_active,
            'is_paused': monitoring_state.is_paused
        },
        'metrics': monitoring_state.metrics,
        'activities': monitoring_state.activities[:1000],  # Limit export size
        'processes': list(monitoring_state.processes.values()),
        'connections': list(monitoring_state.connections.values())
    }
    
    if export_format == 'json':
        return jsonify({
            'success': True,
            'data': data,
            'format': 'json'
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Unsupported export format'
        }), 400

@monitoring_bp.route('/events/stream', methods=['GET'])
def stream_events():
    """Server-Sent Events endpoint for real-time updates"""
    def event_stream():
        while True:
            try:
                # Get event from queue (with timeout)
                event = monitoring_state.event_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                # Send keepalive
                yield f"data: {json.dumps({'type': 'keepalive', 'timestamp': time.time()})}\n\n"
            except Exception as e:
                logger.error(f"Error in event stream: {e}")
                break
    
    from flask import Response
    return Response(event_stream(), mimetype='text/event-stream')

# WebSocket handlers (if Flask-SocketIO is available)
def setup_websocket_handlers(socketio):
    """Setup WebSocket handlers for real-time monitoring"""
    
    @socketio.on('monitoring_subscribe')
    def handle_monitoring_subscribe():
        """Subscribe to monitoring updates"""
        monitoring_state.subscribers.add(request.sid)
        logger.info(f"Client {request.sid} subscribed to monitoring")
        
        # Send current status
        socketio.emit('monitoring_status', {
            'is_active': monitoring_state.is_active,
            'is_paused': monitoring_state.is_paused,
            'metrics': monitoring_state.metrics
        }, room=request.sid)
    
    @socketio.on('monitoring_unsubscribe')
    def handle_monitoring_unsubscribe():
        """Unsubscribe from monitoring updates"""
        monitoring_state.subscribers.discard(request.sid)
        logger.info(f"Client {request.sid} unsubscribed from monitoring")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnect"""
        monitoring_state.subscribers.discard(request.sid)
    
    def broadcast_monitoring_update(data):
        """Broadcast monitoring update to all subscribers"""
        if monitoring_state.subscribers:
            socketio.emit('monitoring_update', data, room=list(monitoring_state.subscribers))
    
    return broadcast_monitoring_update

# Integration function for main app
def register_monitoring_api(app):
    """Register monitoring API with Flask app"""
    app.register_blueprint(monitoring_bp)
    
    # Setup WebSocket if available
    if hasattr(app, 'socketio'):
        setup_websocket_handlers(app.socketio)
    
    logger.info("Monitoring API registered")

# Cleanup function
def cleanup_monitoring():
    """Cleanup monitoring resources"""
    if monitoring_state.is_active:
        monitoring_state.is_active = False
        logger.info("Monitoring cleanup completed")

# Health check endpoint
@monitoring_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'monitoring_active': monitoring_state.is_active,
        'thread_alive': monitoring_state.monitor_thread.is_alive() if monitoring_state.monitor_thread else False,
        'queue_size': monitoring_state.event_queue.qsize(),
        'subscribers': len(monitoring_state.subscribers)
    })

# Statistics endpoint
@monitoring_bp.route('/stats', methods=['GET'])
def get_statistics():
    """Get detailed monitoring statistics"""
    if not monitoring_state.start_time:
        return jsonify({
            'success': False,
            'error': 'Monitoring session not started'
        }), 400
    
    uptime = (datetime.now() - monitoring_state.start_time).total_seconds()
    
    # Calculate event statistics
    event_categories = {}
    event_severities = {}
    
    for activity in monitoring_state.activities:
        category = activity['category']
        severity = activity['severity']
        
        event_categories[category] = event_categories.get(category, 0) + 1
        event_severities[severity] = event_severities.get(severity, 0) + 1
    
    # Calculate rates
    events_per_minute = (monitoring_state.metrics['total_events'] / (uptime / 60)) if uptime > 0 else 0
    suspicious_rate = (monitoring_state.metrics['suspicious_events'] / monitoring_state.metrics['total_events'] * 100) if monitoring_state.metrics['total_events'] > 0 else 0
    
    stats = {
        'session': {
            'start_time': monitoring_state.start_time.isoformat(),
            'uptime_seconds': uptime,
            'uptime_formatted': str(timedelta(seconds=int(uptime))),
            'is_active': monitoring_state.is_active,
            'is_paused': monitoring_state.is_paused
        },
        'events': {
            'total': monitoring_state.metrics['total_events'],
            'suspicious': monitoring_state.metrics['suspicious_events'],
            'per_minute': round(events_per_minute, 2),
            'per_second': monitoring_state.metrics['events_per_second'],
            'suspicious_rate_percent': round(suspicious_rate, 2)
        },
        'categories': event_categories,
        'severities': event_severities,
        'system': {
            'processes_tracked': monitoring_state.metrics['processes'],
            'connections_tracked': monitoring_state.metrics['connections'],
            'cpu_usage': monitoring_state.metrics['cpu_usage'],
            'memory_usage': monitoring_state.metrics['memory_usage']
        },
        'api': {
            'active_subscribers': len(monitoring_state.subscribers),
            'queue_size': monitoring_state.event_queue.qsize()
        }
    }
    
    return jsonify({
        'success': True,
        'data': stats
    })

# Configuration endpoint
@monitoring_bp.route('/config', methods=['GET', 'POST'])
def monitoring_config():
    """Get or update monitoring configuration"""
    if request.method == 'GET':
        config = {
            'event_frequency': 'normal',  # slow, normal, fast
            'max_activities': 1000,
            'max_processes': 500,
            'max_connections': 500,
            'enable_simulation': True,  # For demo mode
            'severity_filter': 'all',
            'category_filter': 'all'
        }
        return jsonify({'success': True, 'data': config})
    
    elif request.method == 'POST':
        # Update configuration
        config_data = request.get_json()
        if not config_data:
            return jsonify({'success': False, 'error': 'No configuration data provided'}), 400
        
        # Validate and apply configuration
        # This would update monitoring behavior in a real implementation
        logger.info(f"Monitoring configuration updated: {config_data}")
        
        return jsonify({'success': True, 'message': 'Configuration updated'})

if __name__ == '__main__':
    # For testing the monitoring API independently
    from flask import Flask
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    register_monitoring_api(app)
    
    @app.route('/')
    def index():
        return jsonify({
            'message': 'Shikra Monitoring API',
            'version': '1.0.0',
            'endpoints': [
                '/api/v1/monitoring/status',
                '/api/v1/monitoring/start',
                '/api/v1/monitoring/stop',
                '/api/v1/monitoring/activities',
                '/api/v1/monitoring/processes',
                '/api/v1/monitoring/connections',
                '/api/v1/monitoring/metrics',
                '/api/v1/monitoring/stats'
            ]
        })
    
    print("Starting Shikra Monitoring API test server...")
    app.run(debug=True)