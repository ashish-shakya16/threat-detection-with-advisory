"""Tests for ML models."""

import pytest
import numpy as np
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ml_models.feature_extractor import FeatureExtractor
from src.ml_models.anomaly_detector import AnomalyDetector
from src.ml_models.model_trainer import ModelTrainer


@pytest.fixture
def sample_events():
    """Generate sample events for testing"""
    events = []
    for i in range(50):
        events.append({
            'cpu_percent': np.random.uniform(10, 40),
            'memory_percent': np.random.uniform(20, 50),
            'num_connections': np.random.randint(1, 10),
            'num_files': np.random.randint(5, 20)
        })
    for i in range(5):
        events.append({
            'cpu_percent': 95.0,
            'memory_percent': 90.0,
            'num_connections': 100,
            'num_files': 500
        })
    return events


def test_feature_extractor():
    """Test feature extraction"""
    extractor = FeatureExtractor()
    process_info = {'cpu_percent': 50.0, 'memory_percent': 30.0}
    features = extractor.extract_from_process(process_info)
    assert len(features) == len(extractor.get_feature_names())
    assert features[0] == 50.0


def test_anomaly_detector_training(sample_events):
    """Test model training"""
    extractor = FeatureExtractor()
    X = extractor.extract_from_batch(sample_events)

    detector = AnomalyDetector()
    detector.train(X)
    assert detector.is_trained


def test_anomaly_detector_prediction(sample_events):
    """Test anomaly prediction"""
    extractor = FeatureExtractor()
    X = extractor.extract_from_batch(sample_events)

    detector = AnomalyDetector()
    detector.train(X)
    predictions = detector.predict(X)
    assert len(predictions) == len(sample_events)
    assert -1 in predictions


def test_model_trainer(sample_events):
    """Test complete training pipeline"""
    trainer = ModelTrainer()

    result = trainer.train_from_events(sample_events)
    assert result['success']

    predictions = trainer.predict_anomalies(sample_events[:10])
    assert len(predictions) == 10
    assert 'is_anomaly' in predictions[0]
    assert 'anomaly_score' in predictions[0]
