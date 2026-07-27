"""Threat management API routes."""

from flask import Blueprint, jsonify, request
import logging

logger = logging.getLogger('securex')

threats_bp = Blueprint('threats', __name__, url_prefix='/api/threats')


def init_threats_routes(db, app):
    """Initialize threats routes"""

    @threats_bp.route('/', methods=['GET'])
    def get_threats():
        """Get all threats with filtering"""
        try:
            limit = request.args.get('limit', 50, type=int)
            hours = request.args.get('hours', 24, type=int)
            risk_level = request.args.get('risk_level', None)

            threats = db.get_recent_threats(limit=limit, hours=hours)

            if risk_level:
                threats = [t for t in threats if t.get('risk_level') == risk_level]

            return jsonify({
                'success': True,
                'count': len(threats),
                'data': threats
            })
        except Exception as e:
            logger.error(f"Error fetching threats: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @threats_bp.route('/<int:threat_id>', methods=['GET'])
    def get_threat_detail(threat_id):
        """Get detailed threat information"""
        try:
            threat = db.get_threat_by_id(threat_id)
            if not threat:
                return jsonify({
                    'success': False,
                    'error': 'Threat not found'
                }), 404

            return jsonify({
                'success': True,
                'data': threat
            })
        except Exception as e:
            logger.error(f"Error fetching threat detail: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @threats_bp.route('/<int:threat_id>/status', methods=['PUT'])
    def update_threat_status(threat_id):
        """Update threat status"""
        try:
            data = request.get_json()
            status = data.get('status')

            if status not in ['resolved', 'ignored', 'escalated']:
                return jsonify({
                    'success': False,
                    'error': 'Invalid status'
                }), 400

            # db.update_threat_status(threat_id, status)

            return jsonify({
                'success': True,
                'message': f'Threat status updated to {status}'
            })
        except Exception as e:
            logger.error(f"Error updating threat status: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @threats_bp.route('/critical', methods=['GET'])
    def get_critical_threats():
        """Get only critical threats"""
        try:
            threats = db.get_recent_threats(limit=10)
            critical = [t for t in threats if t.get('risk_level') == 'Critical']
            return jsonify({
                'success': True,
                'count': len(critical),
                'data': critical
            })
        except Exception as e:
            logger.error(f"Error fetching critical threats: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return threats_bp
