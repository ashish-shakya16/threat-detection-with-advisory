"""
Cybersecurity Threat Advisor - Web Dashboard
Professional Flask-based web interface with real-time monitoring
"""

import os
import sys
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.utils import Config, Logger, load_rules
from src.database.db_manager import DatabaseManager
from src.monitors.system_monitor import SystemMonitor
from src.monitors.network_monitor import NetworkMonitor
from src.detection.rule_engine import RuleEngine
from src.risk_assessment.risk_scorer import RiskScorer
from src.advisory.advisor import SecurityAdvisor
from src.assistant.ai_assistant import AIAssistant

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersecurity-threat-advisor-2026'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global monitoring flag
monitoring_active = False
monitor_thread = None

# Initialize backend modules
config = Config('config/config.yaml')
logger = Logger.setup_logging(config)
rules_data = load_rules(config.get('detection.rule_based.rules_file', 'config/rules.json'))
db = DatabaseManager(config.get('database.path', 'data/db/threats.db'))
system_monitor = SystemMonitor(config.config)
network_monitor = NetworkMonitor(config.config)
rule_engine = RuleEngine(rules_data)
risk_scorer = RiskScorer(config.config)
advisor = SecurityAdvisor(rules_data['advisory_templates'], config.config)
ai_assistant = AIAssistant(db, config.config)

logger.info("Flask Dashboard initialized")


# ==================== WEB ROUTES ====================

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/threats')
def threats_page():
    """Threats list page"""
    return render_template('threats.html')

@app.route('/analytics')
def analytics_page():
    """Analytics and reports page"""
    return render_template('analytics.html')

@app.route('/assistant')
def assistant_page():
    """AI Security Assistant page"""
    return render_template('assistant.html')

@app.route('/settings')
def settings_page():
    """Settings and configuration page"""
    return render_template('settings.html')


# ==================== API ENDPOINTS ====================

@app.route('/api/stats')
def get_stats():
    """Get threat statistics"""
    try:
        stats = db.get_threat_statistics()
        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/threats')
def get_threats():
    """Get recent threats"""
    try:
        limit = int(request.args.get('limit', 50))
        hours = int(request.args.get('hours', 24))
        threats = db.get_recent_threats(limit=limit, hours=hours)
        return jsonify({
            'success': True,
            'data': threats
        })
    except Exception as e:
        logger.error(f"Error getting threats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/threat/<int:threat_id>')
def get_threat_detail(threat_id):
    """Get detailed information about a specific threat"""
    try:
        threat = db.get_threat_by_id(threat_id)
        if threat:
            # Get advisory information
            advisory = db.get_advisory_for_threat(threat_id)
            threat['advisory'] = advisory
            
            return jsonify({
                'success': True,
                'data': threat
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Threat not found'
            }), 404
    except Exception as e:
        logger.error(f"Error getting threat detail: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/system-metrics')
def get_system_metrics():
    """Get current system metrics"""
    try:
        import psutil
        
        metrics = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'network_connections': len(psutil.net_connections()),
            'process_count': len(psutil.pids()),
            'timestamp': datetime.now(timezone.utc).astimezone().isoformat()
        }
        
        return jsonify({
            'success': True,
            'data': metrics
        })
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/threat-timeline')
def get_threat_timeline():
    """Get threat timeline data for charts"""
    try:
        hours = int(request.args.get('hours', 24))
        threats = db.get_recent_threats(limit=1000, hours=hours)
        
        # Group by hour
        timeline = {}
        for threat in threats:
            timestamp = datetime.fromisoformat(threat['timestamp'])
            hour_key = timestamp.strftime('%Y-%m-%d %H:00')
            
            if hour_key not in timeline:
                timeline[hour_key] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            timeline[hour_key]['count'] += 1
            severity = threat['severity'].lower()
            if severity in timeline[hour_key]:
                timeline[hour_key][severity] += 1
        
        # Convert to sorted list
        timeline_list = [
            {'time': k, **v} 
            for k, v in sorted(timeline.items())
        ]
        
        return jsonify({
            'success': True,
            'data': timeline_list
        })
    except Exception as e:
        logger.error(f"Error getting threat timeline: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a single scan"""
    try:
        threats_detected = perform_scan()
        return jsonify({
            'success': True,
            'message': f'Scan complete: {len(threats_detected)} threats detected',
            'threats': threats_detected
        })
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/monitoring/status')
def get_monitoring_status():
    """Get current monitoring status"""
    return jsonify({
        'success': True,
        'data': {
            'active': monitoring_active,
            'timestamp': datetime.now().isoformat()
        }
    })

@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start continuous monitoring"""
    global monitoring_active, monitor_thread
    
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        return jsonify({
            'success': True,
            'message': 'Monitoring started'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Monitoring already active'
        })

@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop continuous monitoring"""
    global monitoring_active
    
    if monitoring_active:
        monitoring_active = False
        return jsonify({
            'success': True,
            'message': 'Monitoring stopped'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Monitoring not active'
        })

@app.route('/api/assistant/chat', methods=['POST'])
def assistant_chat():
    """Handle AI assistant chat requests"""
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        if not user_message:
            return jsonify({
                'success': False,
                'error': 'Message is required'
            }), 400
        
        # Get AI response
        response = ai_assistant.process_query(user_message)
        
        return jsonify({
            'success': True,
            'response': response
        })
    except Exception as e:
        logger.error(f"Error in AI assistant: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to process your request'
        }), 500


# ==================== BACKEND LOGIC ====================

def perform_scan():
    """
    Perform a single threat detection scan
    Returns list of threats detected
    """
    all_threats = []
    
    # Step 1: Collect events from monitors
    system_results = system_monitor.scan_system()
    network_results = network_monitor.scan_network()
    
    # Extract event lists from results
    all_events = []
    all_events.extend(system_results.get('suspicious_processes', []))
    all_events.extend(system_results.get('high_resource_usage', []))
    all_events.extend(system_results.get('new_processes', []))
    all_events.extend(network_results.get('suspicious_ports', []))
    all_events.extend(network_results.get('excessive_connections', []))
    all_events.extend(network_results.get('unusual_destinations', []))
    
    logger.info(f"Dashboard scan: {len(all_events)} events collected")
    
    # Step 2: Detect threats using rule engine
    for event in all_events:
        threat = rule_engine.check_event(event)
        
        if threat:
            # Step 3: Calculate risk score
            threat_with_risk = risk_scorer.calculate_risk(threat)
            
            # Step 4: Generate advisory
            advisory = advisor.generate_advisory(threat_with_risk)
            
            # Step 5: Log to database
            threat_id = db.log_threat(threat_with_risk)
            if advisory:
                db.log_advisory(threat_id, advisory)
            
            all_threats.append({
                'id': threat_id,
                'name': threat_with_risk['threat_name'],
                'severity': threat_with_risk['severity'],
                'risk_level': threat_with_risk.get('risk_level', 'Unknown'),
                'risk_score': threat_with_risk.get('risk_score', 0),
                'timestamp': threat_with_risk['timestamp']
            })
    
    return all_threats

def monitoring_loop():
    """Continuous monitoring loop that runs in background"""
    global monitoring_active
    
    logger.info("Monitoring loop started")
    
    while monitoring_active:
        try:
            # Perform scan
            threats = perform_scan()
            
            # Emit real-time update to all connected clients
            if threats:
                socketio.emit('new_threats', {
                    'count': len(threats),
                    'threats': threats,
                    'timestamp': datetime.now(timezone.utc).astimezone().isoformat()
                })
                
                logger.info(f"Monitoring loop: {len(threats)} threats detected and broadcasted")
            
            # Also emit system metrics
            try:
                import psutil
                metrics = {
                    'cpu': psutil.cpu_percent(interval=0.5),
                    'memory': psutil.virtual_memory().percent,
                    'timestamp': datetime.now().isoformat()
                }
                socketio.emit('system_metrics', metrics)
            except:
                pass
            
            # Wait before next scan
            interval = config.get('monitoring.system.interval', 5)
            time.sleep(interval)
            
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            time.sleep(5)
    
    logger.info("Monitoring loop stopped")


# ==================== SOCKETIO EVENTS ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Threat Advisor'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('request_update')
def handle_request_update():
    """Handle client request for immediate update"""
    try:
        stats = db.get_threat_statistics()
        emit('stats_update', stats)
    except Exception as e:
        logger.error(f"Error sending update: {e}")


# ==================== UTILITY FUNCTIONS ====================

def add_get_threat_by_id_to_db():
    """Add missing method to DatabaseManager if needed"""
    if not hasattr(db, 'get_threat_by_id'):
        def get_threat_by_id(self, threat_id):
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM threats WHERE id = ?
            ''', (threat_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return dict(row)
            return None
        
        # Add method to instance
        import types
        db.get_threat_by_id = types.MethodType(get_threat_by_id, db)

# Add the method
add_get_threat_by_id_to_db()


# ==================== MAIN ====================

if __name__ == '__main__':
    print("=" * 70)
    print("  Cybersecurity Threat Advisor - Web Dashboard")
    print("=" * 70)
    print(f"  Dashboard URL: http://localhost:5000")
    print(f"  Backend: Integrated monitoring system")
    print(f"  Real-time: WebSocket enabled")
    print("=" * 70)
    print()
    
    # Run Flask app with SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
