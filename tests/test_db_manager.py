"""Unit tests for DatabaseManager."""

import os
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager


class TestDatabaseManager(unittest.TestCase):
    """Tests for DatabaseManager against the real schema.sql."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.remove(self.db_path)  # DatabaseManager creates it fresh
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_log_advisory_matches_schema_columns(self):
        threat_id = self.db.log_threat({
            'threat_name': 'Test Threat',
            'category': 'test',
            'severity': 'high',
            'risk_level': 'High',
            'risk_score': 0.9,
            'confidence': 0.8,
        })

        advisory_id = self.db.log_advisory(threat_id, {
            'title': 'Test Advisory',
            'description': 'A test advisory',
            'advice': ['do this', 'do that'],
            'remediation': 'restart the service',
            'references': ['https://example.com'],
        })

        self.assertIsInstance(advisory_id, int)

        fetched = self.db.get_advisory_for_threat(threat_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched['title'], 'Test Advisory')


if __name__ == '__main__':
    unittest.main()
