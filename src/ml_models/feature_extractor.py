"""Feature extraction for ML models."""

import numpy as np
from typing import Dict, List


class FeatureExtractor:
    """Extract ML features from system events"""

    def __init__(self):
        self.feature_names = [
            'cpu_usage',
            'memory_usage',
            'process_count',
            'network_connections',
            'suspicious_port_count',
            'file_operations',
            'registry_changes'
        ]

    def extract_from_process(self, process_info: Dict) -> np.ndarray:
        """Extract features from a process"""
        features = [
            float(process_info.get('cpu_percent', 0)),
            float(process_info.get('memory_percent', 0)),
            1.0,
            float(process_info.get('num_connections', 0)),
            0.0,
            float(process_info.get('num_files', 0)),
            0.0
        ]
        return np.array(features)

    def extract_from_batch(self, events: List[Dict]) -> np.ndarray:
        """Extract features from multiple events"""
        if not events:
            return np.array([]).reshape(0, len(self.feature_names))

        features_list = []
        for event in events:
            features = self.extract_from_process(event)
            features_list.append(features)

        return np.array(features_list)

    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return self.feature_names
