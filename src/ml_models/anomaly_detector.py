"""ML-based anomaly detection using Isolation Forest."""

import hashlib
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


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

    @staticmethod
    def _compute_checksum(path: str) -> str:
        """Compute SHA-256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def save_model(self, path: str) -> None:
        """Save trained model to disk using joblib, with a SHA-256 checksum sidecar file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)

        checksum = self._compute_checksum(path)
        with open(path + '.sha256', 'w') as f:
            f.write(checksum)

    def load_model(self, path: str) -> None:
        """
        Load trained model from disk, verifying its SHA-256 checksum first.

        Raises:
            FileNotFoundError: If the model file or its checksum sidecar is missing.
            ValueError: If the file's checksum doesn't match the recorded checksum,
                indicating the model file was modified or corrupted after saving.
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {path}")

        checksum_path = path + '.sha256'
        if not os.path.exists(checksum_path):
            raise ValueError(
                f"Checksum file not found: {checksum_path}. "
                "Refusing to load a model with no integrity record."
            )

        with open(checksum_path, 'r') as f:
            expected_checksum = f.read().strip()

        actual_checksum = self._compute_checksum(path)
        if actual_checksum != expected_checksum:
            raise ValueError(
                f"Model file checksum mismatch for {path}. "
                "The file may have been tampered with or corrupted. Refusing to load."
            )

        self.model = joblib.load(path)
        self.is_trained = True
