"""ML-based anomaly detection using Isolation Forest."""

import numpy as np
from sklearn.ensemble import IsolationForest
import os
import pickle
from typing import Dict, List


class AnomalyDetector:
    """ML-based anomaly detection using Isolation Forest"""

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        """Initialize anomaly detector"""
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100
        )
        self.is_trained = False

    def train(self, X: np.ndarray) -> None:
        """Train the Isolation Forest model"""
        if X.shape[0] < 10:
            raise ValueError("Need at least 10 samples to train model")

        self.model.fit(X)
        self.is_trained = True

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomalies"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        return self.model.predict(X)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        return self.model.decision_function(X)

    def save_model(self, path: str) -> None:
        """Save trained model to disk"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)

    def load_model(self, path: str) -> None:
        """Load trained model from disk"""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {path}")

        with open(path, 'rb') as f:
            self.model = pickle.load(f)
        self.is_trained = True
