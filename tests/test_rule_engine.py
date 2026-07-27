"""Unit tests for RuleEngine."""

import unittest
from datetime import datetime

from src.detection.rule_engine import RuleEngine


def make_rules():
    return {
        "rules": [
            {
                "id": "TEST_001",
                "name": "Suspicious Process",
                "description": "Test rule",
                "category": "Malware",
                "severity": "high",
                "confidence": 0.9,
                "conditions": {
                    "event_type": "process_start",
                    "process_name_contains": ["mimikatz", "nmap"]
                },
                "impact": "system_control",
                "advisory_template": "suspicious_process"
            }
        ],
        "advisory_templates": {}
    }


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine(make_rules())

    def test_check_event_matches_process_name(self):
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'process_start',
            'source': 'system_monitor',
            'data': {'process_name': 'mimikatz.exe', 'pid': 1234}
        }

        threat = self.engine.check_event(event)

        self.assertIsNotNone(threat)
        self.assertEqual(threat['threat_name'], 'Suspicious Process')
        self.assertEqual(threat['severity'], 'high')

    def test_check_event_no_match_returns_none(self):
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'process_start',
            'source': 'system_monitor',
            'data': {'process_name': 'notepad.exe', 'pid': 999}
        }

        threat = self.engine.check_event(event)

        self.assertIsNone(threat)

    def test_check_event_wrong_event_type_no_match(self):
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'network_connection',
            'source': 'network_monitor',
            'data': {'process_name': 'mimikatz.exe'}
        }

        threat = self.engine.check_event(event)

        self.assertIsNone(threat)

    def test_add_rule_missing_required_field_raises(self):
        with self.assertRaises(ValueError):
            self.engine.add_rule({'id': 'BAD_001', 'name': 'Bad Rule'})

    def test_add_rule_duplicate_id_raises(self):
        with self.assertRaises(ValueError):
            self.engine.add_rule({
                'id': 'TEST_001',
                'name': 'Duplicate',
                'conditions': {},
                'severity': 'low'
            })

    def test_remove_rule_returns_true_when_removed(self):
        removed = self.engine.remove_rule('TEST_001')
        self.assertTrue(removed)
        self.assertIsNone(self.engine.get_rule_by_id('TEST_001'))

    def test_remove_rule_returns_false_when_not_found(self):
        removed = self.engine.remove_rule('DOES_NOT_EXIST')
        self.assertFalse(removed)

    def test_malformed_rule_missing_optional_fields_does_not_crash(self):
        # A rule missing 'description'/'category'/'confidence' (added at
        # runtime via add_rule, which only validates id/name/conditions/severity)
        # must not raise KeyError when a matching event is checked.
        engine = RuleEngine({"rules": [], "advisory_templates": {}})
        engine.add_rule({
            'id': 'MINIMAL_001',
            'name': 'Minimal Rule',
            'conditions': {'event_type': 'process_start'},
            'severity': 'low'
        })

        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'process_start',
            'source': 'system_monitor',
            'data': {}
        }

        threat = engine.check_event(event)  # Must not raise KeyError
        self.assertIsNotNone(threat)
        self.assertEqual(threat['description'], '')
        self.assertEqual(threat['category'], 'Unknown')
        self.assertEqual(threat['confidence'], 0.5)


if __name__ == '__main__':
    unittest.main()
