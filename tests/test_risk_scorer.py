"""Unit tests for RiskScorer."""

import unittest

from src.risk_assessment.risk_scorer import RiskScorer


def make_config():
    return {
        'risk_assessment': {
            'weights': {
                'severity': 0.4,
                'confidence': 0.3,
                'impact': 0.2,
                'prevalence': 0.1
            },
            'thresholds': {
                'low': 0.3,
                'medium': 0.6,
                'high': 0.85
            },
            'impact_factors': {
                'data_access': 3,
                'system_control': 5,
                'network_access': 4,
                'privilege_escalation': 5
            }
        }
    }


class TestRiskScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = RiskScorer(make_config())

    def test_calculate_risk_returns_score_and_level(self):
        threat = {
            'threat_name': 'Suspicious Process',
            'category': 'malware',
            'severity': 'high',
            'confidence': 0.9,
            'impact': 'system_control'
        }

        result = self.scorer.calculate_risk(threat)

        self.assertIn('risk_score', result)
        self.assertIn('risk_level', result)
        self.assertGreaterEqual(result['risk_score'], 0.0)
        self.assertLessEqual(result['risk_score'], 1.0)

    def test_low_severity_produces_low_or_medium_risk_level(self):
        threat = {
            'threat_name': 'Minor Event',
            'category': 'resource abuse',
            'severity': 'low',
            'confidence': 0.5,
            'impact': 'unknown'
        }

        result = self.scorer.calculate_risk(threat)

        self.assertIn(result['risk_level'], ('Low', 'Medium'))

    def test_critical_severity_high_confidence_high_impact_produces_high_or_critical(self):
        threat = {
            'threat_name': 'Critical Event',
            'category': 'brute force',
            'severity': 'critical',
            'confidence': 1.0,
            'impact': 'system_control'
        }

        result = self.scorer.calculate_risk(threat)

        self.assertIn(result['risk_level'], ('High', 'Critical'))

    def test_severity_to_score_handles_unknown_severity(self):
        # Should not raise, should fall back to medium (0.5)
        score = self.scorer._severity_to_score('nonsense')
        self.assertEqual(score, 0.5)

    def test_classify_risk_level_boundaries(self):
        self.assertEqual(self.scorer._classify_risk_level(0.0), 'Low')
        self.assertEqual(self.scorer._classify_risk_level(0.29), 'Low')
        self.assertEqual(self.scorer._classify_risk_level(0.3), 'Medium')
        self.assertEqual(self.scorer._classify_risk_level(0.6), 'High')
        self.assertEqual(self.scorer._classify_risk_level(0.85), 'Critical')
        self.assertEqual(self.scorer._classify_risk_level(1.0), 'Critical')

    def test_risk_components_are_recorded(self):
        threat = {
            'threat_name': 'Test',
            'category': 'malware',
            'severity': 'medium',
            'confidence': 0.7,
            'impact': 'data_access'
        }

        result = self.scorer.calculate_risk(threat)

        components = result['risk_components']
        self.assertIn('severity_score', components)
        self.assertIn('confidence_score', components)
        self.assertIn('impact_score', components)
        self.assertIn('prevalence_score', components)


if __name__ == '__main__':
    unittest.main()
