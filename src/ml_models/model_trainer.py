"""Model training and evaluation."""

import numpy as np
from src.ml_models.anomaly_detector import AnomalyDetector
from src.ml_models.feature_extractor import FeatureExtractor
import logging

logger = logging.getLogger('securex')


class ModelTrainer:
    """Train and evaluate anomaly detection models"""

    def __init__(self):
        self.detector = AnomalyDetector(contamination=0.1)
        self.extractor = FeatureExtractor()

    def train_from_events(self, events: list) -> dict:
        """Train model from raw events"""
        logger.info(f"Training anomaly detector with {len(events)} events")

        X = self.extractor.extract_from_batch(events)

        if X.shape[0] < 10:
            logger.warning("Not enough samples to train model")
            return {'success': False, 'error': 'Insufficient samples'}

        try:
            self.detector.train(X)
            logger.info("Model training completed successfully")
            return {
                'success': True,
                'samples_trained': X.shape[0],
                'features_used': X.shape[1]
            }
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {'success': False, 'error': str(e)}

    def predict_anomalies(self, events: list) -> list:
        """Predict anomalies in events"""
        X = self.extractor.extract_from_batch(events)

        if X.shape[0] == 0:
            return []

        predictions = self.detector.predict(X)
        scores = self.detector.decision_function(X)

        results = []
        for i, event in enumerate(events):
            results.append({
                'event': event,
                'is_anomaly': predictions[i] == -1,
                'anomaly_score': float(scores[i]),
                'threat_probability': max(0, -scores[i] / 10)
            })

        return results

    def save(self, model_path: str) -> None:
        """Save trained model"""
        self.detector.save_model(model_path)
        logger.info(f"Model saved to {model_path}")

    def load(self, model_path: str) -> None:
        """Load trained model"""
        self.detector.load_model(model_path)
        logger.info(f"Model loaded from {model_path}")
