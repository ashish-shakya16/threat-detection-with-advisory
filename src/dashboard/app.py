"""
Cybersecurity Threat Advisor - Web Dashboard
Professional Flask-based web interface with real-time monitoring
"""

import os
import sys
import json
import re
import sqlite3
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
from src.auth import login_required, verify_password, hash_password
from src.dashboard.routes.api_threats import init_threats_routes
from src.dashboard.routes.api_stats import init_stats_routes
from src.dashboard.routes.api_analytics import init_analytics_routes
from src.dashboard.routes.api_notifications import init_notifications_routes
from src.dashboard.routes.api_ml import init_ml_routes
from src.dashboard.routes.api_public import init_public_routes
from src.ml_models.ml_integration import MLIntegration
from src.audit import AuditLog
from src.response import ResponseManager, ResponseError
from src.risk_assessment.asset_context import AssetContextResolver
from src.detection.threat_classifier import classify
from src.detection.ransomware_monitor import RansomwareMonitor
from src.detection.behaviour_baseline import BehaviourBaseline
from src.detection.phishing_url import analyze_url

def _load_env_file(path):
    """Load KEY=VALUE lines from .env without overriding real environment
    variables, so secrets such as SMTP credentials can live in .env."""
    if not os.path.isfile(path):
        return
    with open(path, encoding='utf-8') as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value


# Tests must not pick up real credentials.
if os.environ.get('FLASK_ENV') != 'testing':
    _load_env_file(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env'))

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

allowed_origins = os.environ.get(
    'CORS_ALLOWED_ORIGINS',
    'http://localhost:5000,http://127.0.0.1:5000,'
    'http://localhost:5173,http://127.0.0.1:5173'
).split(',')
CORS(app, origins=allowed_origins)


def _disable_websocket_compression():
    """
    Stop simple-websocket from forcing permessage-deflate on every connection.

    simple_websocket.ws hardcodes `AcceptConnection(extensions=[PerMessageDeflate()])`
    without checking what the client actually offered. Browsers advertise
    `permessage-deflate; client_max_window_bits` (the bare parameter, meaning
    "I support this"), and wsproto answers with `client_max_window_bits=15`.
    RFC 7692 forbids returning a value the client did not itself request, so
    Chrome rejects the frames with "Invalid frame header"; Socket.IO then
    silently falls back to HTTP long-polling and real-time updates lag.

    Replacing AcceptConnection in that module with a version that drops the
    extensions makes the server accept connections uncompressed, which all
    clients handle correctly. Socket.IO payloads here are small JSON events,
    so compression buys nothing. Guarded so an upstream fix (or a refactor of
    that module) cannot break startup.
    """
    try:
        import simple_websocket.ws as sw_ws
    except ImportError:  # pragma: no cover - websocket transport unavailable
        return

    original_accept = getattr(sw_ws, 'AcceptConnection', None)
    if original_accept is None:  # pragma: no cover - upstream refactor
        return

    def accept_without_compression(*args, **kwargs):
        kwargs['extensions'] = []
        return original_accept(*args, **kwargs)

    sw_ws.AcceptConnection = accept_without_compression


_disable_websocket_compression()

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
app.config['SECUREX_DB'] = db
audit_log = AuditLog(db.db_path)
app.config['SECUREX_AUDIT'] = audit_log
system_monitor = SystemMonitor(config.config)
network_monitor = NetworkMonitor(config.config)
rule_engine = RuleEngine(rules_data)
RECURRING_THREAT_WINDOW_MINUTES = config.get('monitoring.recurring_threat_window_minutes', 5)
risk_scorer = RiskScorer(config.config)
asset_context = AssetContextResolver(config.config)
response_manager = ResponseManager(db.db_path, audit_log, config.get('response', {}) or {})
# Additional detectors: ransomware-like file activity and a learned baseline
# of normal process behaviour for unknown threats (see src/detection/).
ransomware_monitor = RansomwareMonitor(config.get('ransomware_detection', {}) or {})
behaviour_baseline = BehaviourBaseline(
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(db.db_path))), 'models'),
    config.get('anomaly_baseline', {}) or {},
)
if os.environ.get('FLASK_ENV') != 'testing':
    ransomware_monitor.start()
advisor = SecurityAdvisor(rules_data['advisory_templates'], config.config)
ai_assistant = AIAssistant(db, config.config)
# Load the embedding model in the background so startup is not delayed.
if os.environ.get('FLASK_ENV') != 'testing':
    ai_assistant.retriever.warm_up()

# Initialize ML integration
ml_integration = MLIntegration()

# Initialize notification manager
notification_manager = None
notification_config = config.config.get('notifications', {})
if notification_config:
    try:
        from src.notifications.notification_manager import NotificationManager
        notification_manager = NotificationManager(
            notification_config,
            db=db,
            dashboard_url=os.environ.get('SECUREX_DASHBOARD_URL', 'http://localhost:5000'),
        )
        notification_manager.start_worker()
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
# Public landing-page routes (no login): version and verified release download.
app.register_blueprint(init_public_routes(db.get_system_info().get('version', '')))


# ==================== WEB ROUTES ====================

def audit_event(action, target_type='', target_id='', outcome='success', details=None, actor=None):
    """Record an action by the current dashboard user in the audit log."""
    audit_log.record(
        actor or session.get('username', 'anonymous'),
        action, target_type, target_id, outcome, details,
        request.remote_addr if request else '',
    )


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
        audit_event('auth.login', 'user', username)
        return jsonify({'success': True, 'data': {'username': username}})

    audit_event('auth.login', 'user', str(username)[:100], 'failure', actor=str(username)[:100] or 'anonymous')
    return jsonify({'success': False, 'error': 'Invalid username or password'}), 401


USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')
EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
MIN_PASSWORD_LENGTH = 8


@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    """Create a new user account, save it, and sign the user in"""
    data = request.get_json() or {}
    username = str(data.get('username', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))

    if not USERNAME_PATTERN.match(username):
        error = 'Username must be 3-32 characters: letters, numbers, dot, dash or underscore'
    elif len(email) > 254 or not EMAIL_PATTERN.match(email):
        error = 'Enter a valid email address'
    elif len(password) < MIN_PASSWORD_LENGTH:
        error = f'Password must be at least {MIN_PASSWORD_LENGTH} characters'
    elif len(password) > 128:
        error = 'Password must be at most 128 characters'
    else:
        error = None
    if error:
        return jsonify({'success': False, 'error': error}), 400

    try:
        db.create_user(username, email, hash_password(password))
    except sqlite3.IntegrityError:
        audit_event('auth.signup', 'user', username[:100], 'failure', actor=username[:100])
        return jsonify({'success': False, 'error': 'That username or email is already registered'}), 409

    session['username'] = username
    db.update_last_login(username)
    audit_event('auth.signup', 'user', username, actor=username)
    return jsonify({'success': True, 'data': {'username': username}}), 201


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """JSON logout endpoint for the SPA"""
    if 'username' in session:
        audit_event('auth.logout', 'user', session['username'])
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
        audit_event('scan.run', details={'threats_detected': len(threats_detected)})
        return jsonify({
            'success': True,
            'data': {
                'message': f'Scan complete: {len(threats_detected)} threats detected',
                'threats': threats_detected
            }
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
        audit_event('monitoring.start')
        return jsonify({
            'success': True,
            'data': {'message': 'Monitoring started'}
        })
    else:
        return jsonify({
            'success': True,
            'data': {'message': 'Monitoring already active'}
        })

@app.route('/api/monitoring/stop', methods=['POST'])
@login_required
def stop_monitoring():
    """Stop continuous monitoring"""
    global monitoring_active
    
    if monitoring_active:
        monitoring_active = False
        audit_event('monitoring.stop')
        return jsonify({
            'success': True,
            'data': {'message': 'Monitoring stopped'}
        })
    else:
        return jsonify({
            'success': True,
            'data': {'message': 'Monitoring not active'}
        })

@app.route('/api/assistant/chat', methods=['POST'])
@login_required
def assistant_chat():
    """Handle AI assistant chat requests"""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = {}
        user = db.get_user_by_username(session['username'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 403
        result = ai_assistant.answer_question_details(data.get('message', ''), user_id=user['id'])
        
        return jsonify({
            'success': True,
            'data': result,
            # Top-level copy kept for older clients that read json.response.
            **result,
        })
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error in AI assistant: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to process your request'
        }), 500


@app.route('/api/assistant/history', methods=['GET'])
@login_required
def assistant_history():
    """Return conversation history for the authenticated user only."""
    user = db.get_user_by_username(session['username'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 403
    try:
        limit = min(max(int(request.args.get('limit', 50)), 1), 100)
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid limit'}), 400
    return jsonify({
        'success': True,
        'data': ai_assistant.get_conversation_history(user['id'], limit),
    })


@app.route('/api/assistant/history', methods=['DELETE'])
@login_required
def clear_assistant_history():
    """Delete the authenticated user's conversation history (other users' is untouched)."""
    user = db.get_user_by_username(session['username'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 403
    deleted = db.delete_conversations_for_user(user['id'])
    audit_event('assistant.history_cleared', 'user', session['username'], details={'deleted': deleted})
    return jsonify({'success': True, 'data': {'deleted': deleted}})


@app.route('/api/assistant/explain/<int:threat_id>', methods=['GET'])
@login_required
def assistant_explain_threat(threat_id):
    """Explain a stored threat without granting the assistant action access."""
    threat = db.get_threat_by_id(threat_id)
    if not threat:
        return jsonify({'success': False, 'error': 'Threat not found'}), 404
    try:
        result = ai_assistant.explain_threat_details(threat, db.get_advisory_for_threat(threat_id))
        audit_event('assistant.explain', 'threat', threat_id, details={'mode': result['mode']})
    except Exception as e:
        logger.error(f"Error explaining threat {threat_id}: {e}")
        return jsonify({'success': False, 'error': 'Failed to explain threat'}), 500
    return jsonify({'success': True, 'data': result})


# ==================== AUDIT & RESPONSE ====================

def _int_arg(name, default, low, high):
    try:
        return min(max(int(request.args.get(name, default)), low), high)
    except ValueError:
        raise ValueError(f'Invalid {name}')


@app.route('/api/audit', methods=['GET'])
@login_required
def list_audit_log():
    """Audit trail, newest first. Filters: action (prefix), actor."""
    try:
        limit = _int_arg('limit', 50, 1, 200)
        offset = _int_arg('offset', 0, 0, 10_000_000)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    return jsonify({'success': True, 'data': audit_log.list(
        limit, offset, request.args.get('action', '')[:100], request.args.get('actor', '')[:100]
    )})


@app.route('/api/audit/verify', methods=['GET'])
@login_required
def verify_audit_log():
    """Recompute the hash chain to detect edited or deleted entries."""
    result = audit_log.verify_chain()
    audit_event('audit.verify', outcome='success' if result['valid'] else 'failure',
                details={'checked': result['checked']})
    return jsonify({'success': True, 'data': result})


@app.route('/api/responses', methods=['GET'])
@login_required
def list_responses():
    """Response proposals and their outcomes. Filters: threat_id, status."""
    try:
        threat_id = request.args.get('threat_id')
        threat_id = int(threat_id) if threat_id else None
        limit = _int_arg('limit', 50, 1, 200)
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid query parameter'}), 400
    return jsonify({
        'success': True,
        'data': response_manager.list(threat_id, request.args.get('status', '')[:20], limit),
        'execution_enabled': response_manager.execution_enabled,
    })


def _decide(proposal_id, decision):
    actor = session['username']
    try:
        result = getattr(response_manager, decision)(proposal_id, actor, request.remote_addr or '')
    except ResponseError as e:
        return jsonify({'success': False, 'error': str(e)}), 409
    except Exception as e:
        logger.error(f"Response {decision} failed for proposal {proposal_id}: {e}")
        return jsonify({'success': False, 'error': 'Response action failed'}), 500
    return jsonify({'success': True, 'data': result})


@app.route('/api/responses/<int:proposal_id>/approve', methods=['POST'])
@login_required
def approve_response(proposal_id):
    """Human approval: re-verifies the target, then executes (or dry-runs)."""
    return _decide(proposal_id, 'approve')


@app.route('/api/responses/<int:proposal_id>/reject', methods=['POST'])
@login_required
def reject_response(proposal_id):
    return _decide(proposal_id, 'reject')


@app.route('/api/responses/<int:proposal_id>/resume', methods=['POST'])
@login_required
def resume_response(proposal_id):
    """Roll back an executed suspension."""
    return _decide(proposal_id, 'resume')


# ==================== DETECTION TOOLS ====================

@app.route('/api/phishing/analyze', methods=['POST'])
@login_required
def analyze_phishing_url():
    """Local phishing analysis of a URL. The URL is never opened or fetched."""
    data = request.get_json(silent=True)
    url = data.get('url') if isinstance(data, dict) else None
    try:
        result = analyze_url(url)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    # Log the host and verdict only; full URLs can contain private tokens.
    audit_event('phishing.analyze', 'host', result['host'], details={'verdict': result['verdict'],
                                                                     'score': result['score']})
    return jsonify({'success': True, 'data': result})


@app.route('/api/detection/status', methods=['GET'])
@login_required
def detection_status():
    """What each detector is doing right now."""
    return jsonify({'success': True, 'data': {
        'rules': len(rule_engine.rules),
        'anomaly_baseline': behaviour_baseline.status(),
        'ransomware_monitor': ransomware_monitor.status(),
        'monitoring_active': monitoring_active,
    }})


@app.route('/api/detection/baseline/reset', methods=['POST'])
@login_required
def reset_behaviour_baseline():
    """Discard the learned baseline and start learning again."""
    behaviour_baseline.reset()
    audit_event('detection.baseline_reset')
    return jsonify({'success': True, 'data': behaviour_baseline.status()})


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
    
    # Step 2: Candidate detections from every detector, each classified
    # with its evidence and verification status.
    candidates = [threat for threat in (rule_engine.check_event(event) for event in all_events) if threat]
    candidates.extend(ransomware_monitor.drain_alerts())
    try:
        candidates.extend(behaviour_baseline.observe())
    except Exception as e:
        logger.error(f"Behaviour baseline failed: {e}")

    for threat in candidates:
        classify(threat)
        if threat:
            # Step 3: Calculate risk score
            threat_with_risk = risk_scorer.calculate_risk(threat)

            # Step 3b: Adjust for context: off-hours activity (10pm-6am local
            # time), asset criticality, network exposure and privileged
            # accounts. See src/risk_assessment/asset_context.py.
            current_hour = datetime.now().hour
            context = asset_context.resolve(threat_with_risk)
            context['off_hours'] = current_hour >= 22 or current_hour < 6
            threat_with_risk = risk_scorer.adjust_risk_by_context(threat_with_risk, context)
            threat_with_risk['risk_context'] = dict(
                context, adjustments=threat_with_risk.get('risk_adjustments', [])
            )

            # Step 3c: Isolation Forest anomaly score, once a model has been
            # trained (POST /api/ml/train). Blended, never lowers the rule score.
            if ml_integration.model_trained:
                ml_risk = ml_integration.calculate_ml_risk_score(threat_with_risk)
                threat_with_risk = ml_integration.enrich_threat_with_ml_score(threat_with_risk, ml_risk)
                threat_with_risk['risk_level'] = risk_scorer._classify_risk_level(threat_with_risk['risk_score'])
                threat_with_risk['risk_context']['ml_anomaly_score'] = round(ml_risk, 3)

            # Step 4: Merge into an existing ongoing threat if the same
            # threat/source is still active, instead of logging a fresh row
            # every scan cycle (an unchanged condition like sustained high
            # CPU would otherwise flood the threats table with duplicates).
            recurring = db.find_active_recurring_threat(
                threat_with_risk['threat_name'],
                threat_with_risk.get('source', 'Unknown'),
                within_minutes=RECURRING_THREAT_WINDOW_MINUTES
            )

            if recurring:
                db.bump_threat_occurrence(
                    recurring['id'],
                    threat_with_risk.get('risk_score', recurring['risk_score']),
                    threat_with_risk.get('risk_level', recurring['risk_level'])
                )
                threat_id = recurring['id']
                advisory = None
            else:
                # Step 5: Generate advisory and log as a new threat
                advisory = advisor.generate_advisory(threat_with_risk)
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

            # Step 6: Graduated response. High/Critical threats with a live
            # process get containment *proposals* that a user must approve.
            try:
                response_manager.propose_for_threat(threat_id, threat_with_risk)
            except Exception as e:
                logger.error(f"Failed to create response proposals: {e}")

            # Step 7: Queue an email alert. Severity rules and the cooldown
            # inside NotificationManager decide whether anything is sent, so
            # an ongoing recurring threat does not produce repeated emails.
            _queue_threat_notification(threat_with_risk, advisory)

    return all_threats


def _queue_threat_notification(threat, advisory=None):
    """Hand a detected threat to the background email worker."""
    if not notification_manager:
        return
    try:
        alert = dict(threat)
        if advisory:
            alert['advice'] = advisory.get('advice', [])
        notification_manager.enqueue_threat(alert)
    except Exception as e:
        logger.error(f"Failed to queue threat notification: {e}")

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
    """Accept real-time connections only from logged-in dashboard sessions.

    Threat broadcasts and system metrics are sensitive, so an unauthenticated
    client is refused (it receives connect_error).
    """
    if 'username' not in session:
        logger.info('Rejected unauthenticated Socket.IO connection')
        return False
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
    dashboard_host = os.environ.get('HOST', config.get('dashboard.host', '127.0.0.1'))
    dashboard_port = int(os.environ.get('PORT', config.get('dashboard.port', 5000)))
    debug_mode = (
        os.environ.get('FLASK_DEBUG', '').lower() == 'true'
        or (
            config.get('system.debug', False)
            and config.get('system.environment') == 'development'
        )
    )

    print("=" * 70)
    print("  Cybersecurity Threat Advisor - Web Dashboard")
    print("=" * 70)
    print(f"  Dashboard URL: http://{dashboard_host}:{dashboard_port}")
    print(f"  Backend: Integrated monitoring system")
    print(f"  Real-time: WebSocket enabled")
    print(f"  Debug mode: {debug_mode}")
    print("=" * 70)
    print()

    socketio.run(
        app,
        host=dashboard_host,
        port=dashboard_port,
        debug=debug_mode,
        use_reloader=False,
    )
