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


class TestLoginRoute(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.remove(self.db_path)

        os.environ['SECRET_KEY'] = 'test-secret-key'
        os.environ['THREAT_DB_PATH'] = self.db_path

        # Import app fresh so it picks up the env vars set above. The route
        # modules define their Blueprint objects at module level, so they
        # must be reloaded too or Flask refuses to re-register routes on
        # the same (cached) blueprint instance.
        import importlib
        import src.dashboard.routes.api_threats as api_threats
        import src.dashboard.routes.api_stats as api_stats
        import src.dashboard.routes.api_analytics as api_analytics
        import src.dashboard.routes.api_notifications as api_notifications
        import src.dashboard.routes.api_ml as api_ml
        import src.dashboard.app as app_module

        importlib.reload(api_threats)
        importlib.reload(api_stats)
        importlib.reload(api_analytics)
        importlib.reload(api_notifications)
        importlib.reload(api_ml)
        importlib.reload(app_module)

        self.app_module = app_module
        self.app_module.app.config['TESTING'] = True
        self.client = self.app_module.app.test_client()

        from src.auth import hash_password
        self.app_module.db.create_user('testadmin', 'admin@example.com', hash_password('testpass123'))

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.environ.pop('SECRET_KEY', None)
        os.environ.pop('THREAT_DB_PATH', None)

    def test_login_with_correct_credentials_redirects_to_index(self):
        response = self.client.post('/login', data={
            'username': 'testadmin',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, 302)

    def test_login_with_wrong_password_returns_401(self):
        response = self.client.post('/login', data={
            'username': 'testadmin',
            'password': 'wrong'
        })
        self.assertEqual(response.status_code, 401)

    def test_index_requires_login(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])


class TestBlueprintRoutesRequireAuth(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.remove(self.db_path)

        os.environ['SECRET_KEY'] = 'test-secret-key'
        os.environ['THREAT_DB_PATH'] = self.db_path

        import importlib
        import src.dashboard.routes.api_threats as api_threats
        import src.dashboard.routes.api_stats as api_stats
        import src.dashboard.routes.api_analytics as api_analytics
        import src.dashboard.routes.api_notifications as api_notifications
        import src.dashboard.routes.api_ml as api_ml
        import src.dashboard.app as app_module

        importlib.reload(api_threats)
        importlib.reload(api_stats)
        importlib.reload(api_analytics)
        importlib.reload(api_notifications)
        importlib.reload(api_ml)
        importlib.reload(app_module)

        self.app_module = app_module
        self.app_module.app.config['TESTING'] = True
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.environ.pop('SECRET_KEY', None)
        os.environ.pop('THREAT_DB_PATH', None)

    def test_threats_api_returns_401_when_unauthenticated(self):
        response = self.client.get('/api/threats/')
        self.assertEqual(response.status_code, 401)

    def test_stats_api_returns_401_when_unauthenticated(self):
        response = self.client.get('/api/stats/')
        self.assertEqual(response.status_code, 401)

    def test_ml_status_api_returns_401_when_unauthenticated(self):
        response = self.client.get('/api/ml/status')
        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
