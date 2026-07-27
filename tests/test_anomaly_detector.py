"""Unit tests for AnomalyDetector."""

import os
import tempfile
import unittest
import numpy as np

from src.ml_models.anomaly_detector import AnomalyDetector


class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AnomalyDetector(contamination=0.1, random_state=42)
        fd, self.model_path = tempfile.mkstemp(suffix='.joblib')
        os.close(fd)
        os.remove(self.model_path)

    def tearDown(self):
        for path in (self.model_path, self.model_path + '.sha256'):
            if os.path.exists(path):
                os.remove(path)

    def test_train_requires_minimum_samples(self):
        X = np.random.rand(5, 7)
        with self.assertRaises(ValueError):
            self.detector.train(X)

    def test_train_and_predict(self):
        X = np.random.rand(50, 7)
        self.detector.train(X)

        predictions = self.detector.predict(X)
        self.assertEqual(len(predictions), 50)

    def test_save_creates_checksum_file(self):
        X = np.random.rand(50, 7)
        self.detector.train(X)
        self.detector.save_model(self.model_path)

        self.assertTrue(os.path.exists(self.model_path))
        self.assertTrue(os.path.exists(self.model_path + '.sha256'))

    def test_load_succeeds_when_checksum_matches(self):
        X = np.random.rand(50, 7)
        self.detector.train(X)
        self.detector.save_model(self.model_path)

        new_detector = AnomalyDetector()
        new_detector.load_model(self.model_path)

        self.assertTrue(new_detector.is_trained)

    def test_load_rejects_tampered_model_file(self):
        X = np.random.rand(50, 7)
        self.detector.train(X)
        self.detector.save_model(self.model_path)

        # Tamper with the model file after the checksum was recorded
        with open(self.model_path, 'ab') as f:
            f.write(b'tampered bytes')

        new_detector = AnomalyDetector()
        with self.assertRaises(ValueError):
            new_detector.load_model(self.model_path)


if __name__ == '__main__':
    unittest.main()
