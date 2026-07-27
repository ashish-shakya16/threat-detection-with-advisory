"""ML model management API routes."""

from flask import Blueprint, jsonify, request
import logging

from src.auth import login_required

logger = logging.getLogger('securex')

ml_bp = Blueprint('ml', __name__, url_prefix='/api/ml')


def init_ml_routes(ml_integration, db, app):
    """Initialize ML routes"""

    @ml_bp.route('/status', methods=['GET'])
    @login_required
    def get_ml_status():
        """Get ML model status"""
        try:
            if not ml_integration:
                return jsonify({
                    'success': False,
                    'status': 'unavailable'
                })

            stats = ml_integration.get_model_stats()
            return jsonify({
                'success': True,
                'status': stats['status'],
                'trained': stats['trained'],
                'model_path': stats['model_path']
            })
        except Exception as e:
            logger.error(f"Error getting ML status: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @ml_bp.route('/train', methods=['POST'])
    @login_required
    def train_ml_model():
        """Train ML anomaly detection model"""
        try:
            if not ml_integration:
                return jsonify({
                    'success': False,
                    'error': 'ML integration not available'
                }), 400

            # Get historical events
            events = db.get_recent_threats(limit=500, hours=720)
            if len(events) < 50:
                return jsonify({
                    'success': False,
                    'error': f'Insufficient data: {len(events)} events. Need at least 50.'
                }), 400

            success = ml_integration.train_model(events)
            return jsonify({
                'success': success,
                'message': 'Model training completed' if success else 'Model training failed',
                'samples_used': len(events)
            })
        except Exception as e:
            logger.error(f"Error training ML model: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @ml_bp.route('/predict', methods=['POST'])
    @login_required
    def predict_anomaly():
        """Predict if event is anomaly"""
        try:
            if not ml_integration:
                return jsonify({
                    'success': False,
                    'error': 'ML integration not available'
                }), 400

            if not ml_integration.model_trained:
                return jsonify({
                    'success': False,
                    'error': 'Model not trained. Train model first.'
                }), 400

            data = request.get_json()
            event = data.get('event', {})

            score = ml_integration.calculate_ml_risk_score(event)
            return jsonify({
                'success': True,
                'anomaly_score': score,
                'is_anomaly': score > 0.5
            })
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return ml_bp
