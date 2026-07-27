"""Unit tests for FeatureExtractor."""

import unittest
import numpy as np

from src.ml_models.feature_extractor import FeatureExtractor


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()

    def test_feature_names_length_matches_extracted_vector_length(self):
        process_info = {
            'cpu_percent': 50.0,
            'memory_percent': 30.0,
            'num_connections': 5,
            'num_files': 2,
        }

        features = self.extractor.extract_from_process(process_info)

        self.assertEqual(len(features), len(self.extractor.get_feature_names()))

    def test_suspicious_port_count_reflects_actual_suspicious_ports(self):
        process_info = {
            'cpu_percent': 10.0,
            'memory_percent': 10.0,
            'num_connections': 3,
            'num_files': 0,
            'remote_ports': [4444, 80, 5555],  # 4444 and 5555 are suspicious per config/rules.json
        }

        features = self.extractor.extract_from_process(process_info)
        feature_names = self.extractor.get_feature_names()
        port_index = feature_names.index('suspicious_port_count')

        self.assertEqual(features[port_index], 2.0)

    def test_suspicious_port_count_zero_when_no_suspicious_ports(self):
        process_info = {
            'cpu_percent': 10.0,
            'memory_percent': 10.0,
            'num_connections': 1,
            'num_files': 0,
            'remote_ports': [80, 443],
        }

        features = self.extractor.extract_from_process(process_info)
        feature_names = self.extractor.get_feature_names()
        port_index = feature_names.index('suspicious_port_count')

        self.assertEqual(features[port_index], 0.0)

    def test_process_count_defaults_to_one_process(self):
        process_info = {'cpu_percent': 5.0, 'memory_percent': 5.0}

        features = self.extractor.extract_from_process(process_info)
        feature_names = self.extractor.get_feature_names()
        process_count_index = feature_names.index('process_count')

        # A single process_info dict represents exactly one process being scored.
        self.assertEqual(features[process_count_index], 1.0)

    def test_file_operations_uses_real_num_files_value(self):
        process_info = {
            'cpu_percent': 5.0,
            'memory_percent': 5.0,
            'num_files': 17,
        }

        features = self.extractor.extract_from_process(process_info)
        feature_names = self.extractor.get_feature_names()
        file_ops_index = feature_names.index('file_operations')

        self.assertEqual(features[file_ops_index], 17.0)

    def test_extract_from_batch_empty_list_returns_correct_shape(self):
        result = self.extractor.extract_from_batch([])
        self.assertEqual(result.shape, (0, len(self.extractor.get_feature_names())))


if __name__ == '__main__':
    unittest.main()
