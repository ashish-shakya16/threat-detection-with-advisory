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
from flask import Flask, jsonify, request, session, send_from_directory
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
from src.auth import login_required, verify_password
from src.dashboard.routes.api_threats import init_threats_routes
from src.dashboard.routes.api_stats import init_stats_routes
from src.dashboard.routes.api_analytics import init_analytics_routes
from src.dashboard.routes.api_notifications import init_notifications_routes
from src.dashboard.routes.api_ml import init_ml_routes
from src.ml_models.ml_integration import MLIntegration

# Initialize Flask app
app = Flask(__name__)

secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if os.environ.get('FLASK_ENV') == 'testing' or app.config.get('TESTING'):
        secret_key = 'test-only-secret-key-not-for-production'
    else:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and set it: set SECRET_KEY=<value> (Windows) or export SECRET_KEY=<value> (Unix)."
        )
app.config['SECRET_KEY'] = secret_key

allowed_origins = os.environ.get('CORS_ALLOWED_ORIGINS', 'http://localhost:5000').split(',')
CORS(app, origins=allowed_origins)
socketio = SocketIO(app, cors_allowed_origins=allowed_origins)

FRONTEND_DIST = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'frontend', 'dist')

# Global monitoring flag
monitoring_active = False
monitor_thread = None

# Initialize backend modules
config = Config('config/config.yaml')
logger = Logger.setup_logging(config)
rules_data = load_rules(config.get('detection.rule_based.rules_file', 'config/rules.json'))
db = DatabaseManager(os.environ.get('THREAT_DB_PATH') or config.get('database.path', 'data/db/threats.db'))
system_monitor = SystemMonitor(config.config)
network_monitor = NetworkMonitor(config.config)
rule_engine = RuleEngine(rules_data)
risk_scorer = RiskScorer(config.config)
advisor = SecurityAdvisor(rules_data['advisory_templates'], config.config)
ai_assistant = AIAssistant(db, config.config)

# Initialize ML integration
ml_integration = MLIntegration()

# Initialize notification manager
notification_manager = None
notification_config = config.config.get('notifications', {})
if notification_config.get('enabled', False):
    try:
        from src.notifications.notification_manager import NotificationManager
        notification_manager = NotificationManager(notification_config)
    except Exception as e:
        logger.error(f"Failed to initialize notifications: {str(e)}")

logger.info("Flask Dashboard initialized")

# Register API blueprints
threats_bp = init_threats_routes(db, app)
stats_bp = init_stats_routes(db, app)
analytics_bp = init_analytics_routes(db, app)
notifications_bp = init_notifications_routes(notification_manager, app)
ml_bp = init_ml_routes(ml_integration, db, app)

app.register_blueprint(threats_bp)
app.register_blueprint(stats_bp)
app.register_blueprint(analytics_bp)
app.register_blueprint(notifications_bp)
app.register_blueprint(ml_bp)


# ==================== WEB ROUTES ====================

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """JSON login endpoint for the SPA"""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    user = db.get_user_by_username(username)
    if user and verify_password(user['password_hash'], password):
        session['username'] = username
        db.update_last_login(username)
        return jsonify({'success': True, 'data': {'username': username}})

    return jsonify({'success': False, 'error': 'Invalid username or password'}), 401


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """JSON logout endpoint for the SPA"""
    session.pop('username', None)
    return jsonify({'success': True})


@app.route('/api/auth/me')
def api_me():
    """Return the currently authenticated user, or 401 if not logged in"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    return jsonify({'success': True, 'data': {'username': session['username']}})


@app.route('/api/system-info')
@login_required
def api_system_info():
    """Get basic system info for the settings page"""
    try:
        info = db.get_system_info(rules_loaded=len(rules_data.get('rules', [])))
        return jsonify({'success': True, 'data': info})
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== API ENDPOINTS ====================

@app.route('/api/stats')
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
def get_threat_timeline():
    """Get threat timeline data for charts"""
    try:
        hours = int(request.args.get('hours', 24))
        threats = db.get_recent_threats(limit=1000, hours=hours)

        # Group by hour
        timeline = {}
        for threat in threats:
            detected_at = threat.get('detected_at')
            if not detected_at:
                continue
            timestamp = datetime.fromisoformat(detected_at)
            hour_key = timestamp.strftime('%Y-%m-%d %H:00')

            if hour_key not in timeline:
                timeline[hour_key] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

            timeline[hour_key]['count'] += 1
            severity = str(threat.get('severity', '')).lower()
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
        response = ai_assistant.answer_question(user_message)
        
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

            # Step 3b: Adjust for off-hours activity (10pm-6am local time is
            # more suspicious than daytime activity for the same event)
            current_hour = datetime.now().hour
            is_off_hours = current_hour >= 22 or current_hour < 6
            if is_off_hours:
                threat_with_risk = risk_scorer.adjust_risk_by_context(
                    threat_with_risk, {'off_hours': True}
                )

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
            except Exception as e:
                logger.debug(f"Failed to emit system metrics: {e}")
            
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


# ==================== SPA STATIC SERVING ====================

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    """
    Serve the built React SPA for any non-API route.

    In development, the frontend runs on its own Vite dev server (port 5173)
    and this route is never hit for page loads — only used when running the
    production build through Flask directly.
    """
    if path.startswith('api/') or path.startswith('socket.io'):
        return jsonify({'success': False, 'error': 'Not found'}), 404

    full_path = os.path.join(FRONTEND_DIST, path)
    if path and os.path.exists(full_path) and os.path.isfile(full_path):
        return send_from_directory(FRONTEND_DIST, path)

    index_path = os.path.join(FRONTEND_DIST, 'index.html')
    if not os.path.exists(index_path):
        return jsonify({
            'success': False,
            'error': 'Frontend build not found. Run `npm run build` in the frontend/ directory.'
        }), 503

    return send_from_directory(FRONTEND_DIST, 'index.html')


# ==================== MAIN ====================

if __name__ == '__main__':
    dashboard_host = config.get('dashboard.host', '127.0.0.1')
    dashboard_port = config.get('dashboard.port', 5000)
    debug_mode = config.get('system.debug', False) and config.get('system.environment') == 'development'

    print("=" * 70)
    print("  Cybersecurity Threat Advisor - Web Dashboard")
    print("=" * 70)
    print(f"  Dashboard URL: http://{dashboard_host}:{dashboard_port}")
    print(f"  Backend: Integrated monitoring system")
    print(f"  Real-time: WebSocket enabled")
    print(f"  Debug mode: {debug_mode}")
    print("=" * 70)
    print()

    socketio.run(app, host=dashboard_host, port=dashboard_port, debug=debug_mode)
