"""Statistics API routes."""

from flask import Blueprint, jsonify
import logging

logger = logging.getLogger('securex')

stats_bp = Blueprint('stats', __name__, url_prefix='/api/stats')


def init_stats_routes(db, app):
    """Initialize statistics routes"""

    @stats_bp.route('/', methods=['GET'])
    def get_stats():
        """Get overall statistics"""
        try:
            stats = db.get_threat_statistics()
            return jsonify({
                'success': True,
                'data': stats
            })
        except Exception as e:
            logger.error(f"Error fetching stats: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @stats_bp.route('/by-category', methods=['GET'])
    def get_stats_by_category():
        """Get threat statistics by category"""
        try:
            stats = db.get_threat_statistics()
            return jsonify({
                'success': True,
                'data': stats.get('by_category', {})
            })
        except Exception as e:
            logger.error(f"Error fetching category stats: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @stats_bp.route('/by-severity', methods=['GET'])
    def get_stats_by_severity():
        """Get threat statistics by severity"""
        try:
            stats = db.get_threat_statistics()
            return jsonify({
                'success': True,
                'data': stats.get('by_severity', {})
            })
        except Exception as e:
            logger.error(f"Error fetching severity stats: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return stats_bp
