"""Notification management API routes (v1.2)."""

from flask import Blueprint, jsonify, request
import logging

from src.auth import login_required

logger = logging.getLogger('securex')

notifications_bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')


def init_notifications_routes(notification_manager, app):
    """Initialize notifications routes"""

    @notifications_bp.route('/status', methods=['GET'])
    @login_required
    def get_notification_status():
        """Get notification system status"""
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
                'recipients': notification_manager.recipients,
                'notification_rules': {
                    'critical': notification_manager.notify_on_critical,
                    'high': notification_manager.notify_on_high,
                    'medium': notification_manager.notify_on_medium,
                    'low': notification_manager.notify_on_low
                }
            })
        except Exception as e:
            logger.error(f"Error getting notification status: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/recipients', methods=['GET'])
    @login_required
    def get_recipients():
        """Get notification recipients"""
        try:
            if not notification_manager:
                return jsonify({
                    'success': False,
                    'recipients': []
                })

            return jsonify({
                'success': True,
                'recipients': notification_manager.recipients
            })
        except Exception as e:
            logger.error(f"Error getting recipients: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/recipients', methods=['POST'])
    @login_required
    def add_recipient():
        """Add notification recipient"""
        try:
            if not notification_manager:
                return jsonify({
                    'success': False,
                    'error': 'Notification system not initialized'
                }), 400

            data = request.get_json()
            email = data.get('email')

            if not email:
                return jsonify({
                    'success': False,
                    'error': 'Email is required'
                }), 400

            success = notification_manager.add_recipient(email)
            return jsonify({
                'success': success,
                'message': f'Recipient {email} added' if success else 'Failed to add recipient'
            })
        except Exception as e:
            logger.error(f"Error adding recipient: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/recipients/<email>', methods=['DELETE'])
    @login_required
    def remove_recipient(email):
        """Remove notification recipient"""
        try:
            if not notification_manager:
                return jsonify({
                    'success': False,
                    'error': 'Notification system not initialized'
                }), 400

            success = notification_manager.remove_recipient(email)
            return jsonify({
                'success': success,
                'message': f'Recipient {email} removed' if success else 'Recipient not found'
            })
        except Exception as e:
            logger.error(f"Error removing recipient: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/test', methods=['POST'])
    @login_required
    def test_notification():
        """Send test notification"""
        try:
            if not notification_manager:
                return jsonify({
                    'success': False,
                    'error': 'Notification system not initialized'
                }), 400

            test_threat = {
                'threat_name': 'Test Threat',
                'risk_level': 'High',
                'risk_score': 0.85,
                'category': 'Testing',
                'description': 'This is a test notification',
                'timestamp': 'Now',
                'event_data': {'test': 'value'}
            }

            success = notification_manager.notify_threat(test_threat)
            return jsonify({
                'success': success,
                'message': 'Test notification sent' if success else 'Failed to send test notification'
            })
        except Exception as e:
            logger.error(f"Error sending test notification: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return notifications_bp
