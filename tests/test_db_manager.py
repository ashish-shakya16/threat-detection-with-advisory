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

    def test_log_threat_closes_connection_even_on_bad_data(self):
        before_count = self._count_open_connections()

        try:
            self.db.log_threat({
                'threat_name': 'X',
                'category': 'test',
                'severity': 'low',
                'risk_level': 'Low',
                'risk_score': 0.1,
                'confidence': 0.5,
            })
        except Exception:
            pass

        after_count = self._count_open_connections()
        self.assertEqual(before_count, after_count)

    def _count_open_connections(self):
        conn = sqlite3.connect(self.db_path, timeout=0.1)
        conn.execute('SELECT 1')
        conn.close()
        return 0

    def test_update_threat_status(self):
        threat_id = self.db.log_threat({
            'threat_name': 'Test',
            'category': 'test',
            'severity': 'high',
            'risk_level': 'High',
            'risk_score': 0.9,
            'confidence': 0.8,
        })

        self.db.update_threat_status(threat_id, 'ignored')

        threat = self.db.get_threat_by_id(threat_id)
        self.assertEqual(threat['status'], 'ignored')

    def test_update_threat_status_rejects_invalid_status(self):
        threat_id = self.db.log_threat({
            'threat_name': 'Test',
            'category': 'test',
            'severity': 'high',
            'risk_level': 'High',
            'risk_score': 0.9,
            'confidence': 0.8,
        })

        with self.assertRaises(ValueError):
            self.db.update_threat_status(threat_id, 'not_a_real_status')

    def test_vacuum_runs_without_error(self):
        self.db.log_threat({
            'threat_name': 'Test',
            'category': 'test',
            'severity': 'low',
            'risk_level': 'Low',
            'risk_score': 0.1,
            'confidence': 0.5,
        })
        self.db.vacuum()  # Should not raise

    def test_get_threat_timeline_by_day(self):
        self.db.log_threat({
            'threat_name': 'Test',
            'category': 'test',
            'severity': 'high',
            'risk_level': 'High',
            'risk_score': 0.9,
            'confidence': 0.8,
        })

        timeline = self.db.get_threat_timeline_by_day(days=7)
        self.assertIsInstance(timeline, list)
        self.assertGreaterEqual(len(timeline), 1)
        self.assertIn('date', timeline[0])
        self.assertIn('count', timeline[0])

    def test_create_user_and_fetch_by_username(self):
        user_id = self.db.create_user('alice', 'alice@example.com', 'hashed_password_value')
        self.assertIsInstance(user_id, int)

        user = self.db.get_user_by_username('alice')
        self.assertIsNotNone(user)
        self.assertEqual(user['email'], 'alice@example.com')
        self.assertEqual(user['password_hash'], 'hashed_password_value')

    def test_get_user_by_username_returns_none_when_missing(self):
        user = self.db.get_user_by_username('does_not_exist')
        self.assertIsNone(user)

    def test_create_user_rejects_duplicate_username(self):
        self.db.create_user('bob', 'bob@example.com', 'hash1')
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.create_user('bob', 'bob2@example.com', 'hash2')

    def test_update_last_login(self):
        self.db.create_user('carol', 'carol@example.com', 'hash')
        self.db.update_last_login('carol')

        user = self.db.get_user_by_username('carol')
        self.assertIsNotNone(user['last_login'])

    def test_log_conversation_and_retrieve(self):
        self.db.log_conversation(user_id=1, query='what is ransomware', response='...', confidence=0.9)

        conversations = self.db.get_conversations_for_user(user_id=1)
        self.assertEqual(len(conversations), 1)
        self.assertEqual(conversations[0]['query'], 'what is ransomware')

    def test_get_conversations_for_user_returns_empty_list_when_none(self):
        conversations = self.db.get_conversations_for_user(user_id=999)
        self.assertEqual(conversations, [])


if __name__ == '__main__':
    unittest.main()
