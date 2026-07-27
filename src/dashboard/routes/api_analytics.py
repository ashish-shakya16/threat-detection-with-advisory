"""Analytics API routes."""

from flask import Blueprint, jsonify, request
import logging

from src.auth import login_required

logger = logging.getLogger('securex')

analytics_bp = Blueprint('analytics', __name__, url_prefix='/api/analytics')


def init_analytics_routes(db, app):
    """Initialize analytics routes"""

    @analytics_bp.route('/timeline', methods=['GET'])
    @login_required
    def get_threat_timeline():
        """Get threat detection timeline"""
        try:
            days = request.args.get('days', 7, type=int)
            timeline = db.get_threat_timeline_by_day(days=days)
            return jsonify({
                'success': True,
                'data': timeline
            })
        except Exception as e:
            logger.error(f"Error fetching timeline: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @analytics_bp.route('/top-threats', methods=['GET'])
    @login_required
    def get_top_threats():
        """Get most frequent threats"""
        try:
            limit = request.args.get('limit', 10, type=int)
            threats = db.get_recent_threats(limit=limit)
            return jsonify({
                'success': True,
                'data': threats[:limit]
            })
        except Exception as e:
            logger.error(f"Error fetching top threats: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @analytics_bp.route('/detection-rate', methods=['GET'])
    @login_required
    def get_detection_rate():
        """Get detection rate statistics"""
        try:
            period = request.args.get('period', 'daily')
            hours = 24 if period == 'daily' else 24 * 7
            stats = db.get_threat_statistics(hours=hours)
            total = stats.get('total_threats', 0)
            rate = round(total / hours, 3) if hours else 0.0
            return jsonify({
                'success': True,
                'data': {'period': period, 'rate': rate, 'total_threats': total}
            })
        except Exception as e:
            logger.error(f"Error fetching detection rate: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return analytics_bp
