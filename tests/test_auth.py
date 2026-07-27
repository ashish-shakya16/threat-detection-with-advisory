"""Unit tests for authentication helpers."""

import os
import tempfile
import unittest

from flask import Flask, session

from src.auth import hash_password, verify_password, login_required
from src.database.db_manager import DatabaseManager


class TestPasswordHashing(unittest.TestCase):
    def test_hash_password_produces_different_output_than_input(self):
        hashed = hash_password('my-secret-password')
        self.assertNotEqual(hashed, 'my-secret-password')

    def test_verify_password_accepts_correct_password(self):
        hashed = hash_password('correct-horse-battery-staple')
        self.assertTrue(verify_password(hashed, 'correct-horse-battery-staple'))

    def test_verify_password_rejects_wrong_password(self):
        hashed = hash_password('correct-horse-battery-staple')
        self.assertFalse(verify_password(hashed, 'wrong-password'))


class TestLoginRequiredDecorator(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'test-secret'
        self.app.config['TESTING'] = True

        @self.app.route('/login')
        def login():
            return 'login page'

        @self.app.route('/protected')
        @login_required
        def protected():
            return 'secret data'

        self.client = self.app.test_client()

    def test_unauthenticated_request_redirected_to_login(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_authenticated_request_succeeds(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'testuser'

        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'secret data')


if __name__ == '__main__':
    unittest.main()
