"""
ML Model Integration for ThreatAdvisor

Integrates anomaly detection into the threat detection pipeline.
"""

import logging
import os
from typing import Dict, Any, List, Optional

from src.ml_models.model_trainer import ModelTrainer
from src.ml_models.feature_extractor import FeatureExtractor


class MLIntegration:
    """
    Integrates ML-based anomaly detection into threat detection pipeline.

    Provides anomaly scoring alongside rule-based detection for improved accuracy.
    """

    def __init__(self, model_path: str = "src/ml_models/saved_models/anomaly_detector.pkl"):
        """
        Initialize ML integration.

        Args:
            model_path: Path to saved model file
        """
        self.logger = logging.getLogger('SecureX.MLIntegration')
        self.model_path = model_path
        self.trainer = ModelTrainer()
        self.extractor = FeatureExtractor()
        self.model_trained = False

        self._load_or_init_model()

    def _load_or_init_model(self):
        """Load existing model or initialize new one."""
        if os.path.exists(self.model_path):
            try:
                self.trainer.load(self.model_path)
                self.model_trained = True
                self.logger.info("ML model loaded from disk")
            except Exception as e:
                self.logger.warning(f"Failed to load model: {str(e)}")
                self.model_trained = False
        else:
            self.logger.info("No trained model found. Training required.")
            self.model_trained = False

    def train_model(self, events: List[Dict[str, Any]]) -> bool:
        """
        Train anomaly detection model.

        Args:
            events: List of historical events for training

        Returns:
            True if training successful, False otherwise
        """
        if len(events) < 50:
            self.logger.warning(f"Insufficient training data: {len(events)} events. Need at least 50.")
            return False

        try:
            result = self.trainer.train_from_events(events)
            if result['success']:
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                self.trainer.save(self.model_path)
                self.model_trained = True
                self.logger.info(f"Model trained successfully with {result['samples_trained']} samples")
                return True
            else:
                self.logger.error(f"Training failed: {result['error']}")
                return False

        except Exception as e:
            self.logger.error(f"Exception during training: {str(e)}")
            return False

    def detect_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect anomalies in events using trained model.

        Args:
            events: List of events to analyze

        Returns:
            List of events with anomaly scores
        """
        if not self.model_trained:
            self.logger.warning("Model not trained. Anomaly detection disabled.")
            return events

        try:
            predictions = self.trainer.predict_anomalies(events)
            return predictions
        except Exception as e:
            self.logger.error(f"Error during anomaly detection: {str(e)}")
            return events

    def calculate_ml_risk_score(self, event: Dict[str, Any]) -> float:
        """
        Calculate ML-based risk score for an event.

        Args:
            event: Event dictionary

        Returns:
            Risk score between 0 and 1
        """
        if not self.model_trained:
            return 0.0

        try:
            predictions = self.trainer.predict_anomalies([event])
            if predictions:
                return predictions[0].get('threat_probability', 0.0)
            return 0.0
        except Exception as e:
            self.logger.error(f"Error calculating ML score: {str(e)}")
            return 0.0

    def enrich_threat_with_ml_score(self, threat: Dict[str, Any], ml_risk: float) -> Dict[str, Any]:
        """
        Enrich threat data with ML-based risk scoring.

        Args:
            threat: Threat dictionary from rule-based detection
            ml_risk: ML-based risk score (0-1)

        Returns:
            Enhanced threat dictionary
        """
        # Blend rule-based and ML scores (70% rule, 30% ML)
        if 'risk_score' in threat:
            original_score = threat['risk_score']
            blended_score = (original_score * 0.7) + (ml_risk * 0.3)
            threat['ml_score'] = ml_risk
            threat['blended_score'] = blended_score
            threat['risk_score'] = max(original_score, blended_score)

        return threat

    def get_model_stats(self) -> Dict[str, Any]:
        """Get statistics about trained model."""
        return {
            'trained': self.model_trained,
            'model_path': self.model_path,
            'exists': os.path.exists(self.model_path),
            'status': 'Ready' if self.model_trained else 'Not trained'
        }
