"""Notification management API routes (v1.2)."""

from flask import Blueprint, jsonify, request, session, redirect
import logging
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from src.auth import login_required

logger = logging.getLogger('securex')

notifications_bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')

VERIFICATION_TTL_MINUTES = 30


def _audit(app, action, target_type='', target_id='', outcome='success', details=None):
    """Record a dashboard action in the audit log, if one is configured."""
    audit = app.config.get('SECUREX_AUDIT')
    if audit:
        audit.record(session.get('username', 'anonymous'), action, target_type, target_id,
                     outcome, details, request.remote_addr or '')


def init_notifications_routes(notification_manager, app):
    """Initialize notifications routes"""

    def not_initialized():
        return jsonify({
            'success': False,
            'error': 'Notification system not initialized'
        }), 400

    @notifications_bp.route('/status', methods=['GET'])
    @login_required
    def get_notification_status():
        """Get notification system status (never includes SMTP credentials)."""
        try:
            if not notification_manager:
                return jsonify({
                    'success': False,
                    'status': 'disabled',
                    'message': 'Notification system not initialized'
                })

            return jsonify({
                'success': True,
                'status': 'enabled' if notification_manager.enabled else 'disabled',
                'smtp_configured': notification_manager.smtp_configured,
                'recipients': notification_manager.recipients,
                'notification_rules': {
                    'critical': notification_manager.notify_on_critical,
                    'high': notification_manager.notify_on_high,
                    'medium': notification_manager.notify_on_medium,
                    'low': notification_manager.notify_on_low
                },
                'cooldown_seconds': notification_manager.cooldown_seconds,
            })
        except Exception as e:
            logger.error(f"Error getting notification status: {e}")
            return jsonify({
                'success': False,
                'error': 'Failed to load notification status'
            }), 500

    @notifications_bp.route('/preferences', methods=['PATCH'])
    @login_required
    def update_preferences():
        """Update and persist notification preferences."""
        if not notification_manager:
            return not_initialized()
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({'success': False, 'error': 'Invalid preferences'}), 400
        try:
            preferences = notification_manager.update_preferences(data)
        except ValueError as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Error updating notification preferences: {e}")
            return jsonify({'success': False, 'error': 'Failed to update preferences'}), 500
        _audit(app, 'notifications.preferences_update', details=preferences)
        return jsonify({'success': True, 'data': preferences, 'message': 'Notification preferences updated'})

    @notifications_bp.route('/deliveries', methods=['GET'])
    @login_required
    def get_deliveries():
        """Recent email delivery attempts and their status."""
        try:
            limit = min(max(int(request.args.get('limit', 20)), 1), 100)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid limit'}), 400
        db = app.config.get('SECUREX_DB')
        if not db:
            return jsonify({'success': True, 'data': []})
        return jsonify({'success': True, 'data': db.get_recent_notification_deliveries(limit)})

    @notifications_bp.route('/recipients', methods=['GET'])
    @login_required
    def get_recipients():
        """Get notification recipients"""
        if not notification_manager:
            return jsonify({'success': False, 'recipients': []})
        return jsonify({'success': True, 'recipients': notification_manager.recipients})

    @notifications_bp.route('/recipients', methods=['POST'])
    @notifications_bp.route('/recipients/verify/request', methods=['POST'])
    @login_required
    def request_recipient_verification():
        """Send a one-time verification link; the address is only added once verified."""
        try:
            if not notification_manager or not notification_manager.email_service:
                return jsonify({'success': False, 'error': 'Email service is not configured'}), 400
            db = app.config.get('SECUREX_DB')
            if not db:
                return jsonify({'success': False, 'error': 'Database is not available'}), 500
            data = request.get_json(silent=True) or {}
            email = str(data.get('email', '')).strip()
            if not notification_manager.email_service.validate_email(email):
                return jsonify({'success': False, 'error': 'Valid email is required'}), 400
            if email in notification_manager.recipients:
                return jsonify({'success': False, 'error': 'This address is already a verified recipient'}), 400
            user = db.get_user_by_username(session['username'])
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 403

            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            # Stored in UTC to match SQLite's CURRENT_TIMESTAMP comparison.
            expires = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=VERIFICATION_TTL_MINUTES)
            db.create_email_verification(user['id'], email, token_hash, expires.strftime('%Y-%m-%d %H:%M:%S'))
            verify_url = f"{notification_manager.dashboard_url}/api/notifications/verify?token={token}"
            notification_manager.email_service.send_email(
                email,
                'Verify SecureX email alerts',
                '<p>Someone asked to send SecureX security alerts to this address.</p>'
                f'<p><a href="{verify_url}">Verify email address</a></p>'
                f'<p>This link expires in {VERIFICATION_TTL_MINUTES} minutes. '
                'If you did not request this, ignore this email.</p>',
                f'Verify SecureX email alerts: {verify_url}\n'
                f'This link expires in {VERIFICATION_TTL_MINUTES} minutes. '
                'If you did not request this, ignore this email.',
            )
            _audit(app, 'notifications.recipient_verification_requested', 'email', email)
            return jsonify({'success': True, 'message': 'Verification email sent'})
        except Exception as e:
            logger.error(f"Error requesting recipient verification: {e}")
            return jsonify({'success': False, 'error': 'Could not send verification email'}), 500

    @notifications_bp.route('/verify', methods=['GET'])
    def verify_recipient():
        """Consume a verification link (opened from email) and activate the recipient."""
        token = request.args.get('token', '')
        db = app.config.get('SECUREX_DB')
        record = None
        if token and db and notification_manager:
            record = db.consume_email_verification(
                hashlib.sha256(token.encode('utf-8')).hexdigest()
            )
        if not record:
            _audit(app, 'notifications.recipient_verified', outcome='failure')
            return redirect('/settings?email_verified=0')
        if record['email'] not in notification_manager.recipients:
            notification_manager.recipients.append(record['email'])
        logger.info('Notification recipient verified')
        audit = app.config.get('SECUREX_AUDIT')
        if audit:
            audit.record(record['email'], 'notifications.recipient_verified', 'email', record['email'],
                         source_ip=request.remote_addr or '')
        return redirect('/settings?email_verified=1')

    @notifications_bp.route('/recipients/<email>', methods=['DELETE'])
    @login_required
    def remove_recipient(email):
        """Remove notification recipient"""
        try:
            if not notification_manager:
                return not_initialized()

            success = notification_manager.remove_recipient(email)
            _audit(app, 'notifications.recipient_removed', 'email', email, 'success' if success else 'failure')
            return jsonify({
                'success': success,
                'message': f'Recipient {email} removed' if success else 'Recipient not found',
                'error': '' if success else 'Recipient not found',
            })
        except Exception as e:
            logger.error(f"Error removing recipient: {e}")
            return jsonify({
                'success': False,
                'error': 'Failed to remove recipient'
            }), 500

    @notifications_bp.route('/test', methods=['POST'])
    @login_required
    def test_notification():
        """Send a test email to all recipients (ignores severity rules and cooldown)."""
        try:
            if not notification_manager:
                return not_initialized()

            result = notification_manager.send_test_email()
            _audit(app, 'notifications.test_email', outcome='success' if result['success'] else 'failure',
                   details={'recipients': len(result.get('results', {}))})
            return jsonify({
                'success': result['success'],
                'data': result,
                'message': 'Test notification sent' if result['success'] else 'Failed to send test notification',
                'error': result.get('error', ''),
            }), (200 if result['success'] else 502)
        except Exception as e:
            logger.error(f"Error sending test notification: {e}")
            return jsonify({
                'success': False,
                'error': 'Failed to send test notification'
            }), 500

    return notifications_bp
