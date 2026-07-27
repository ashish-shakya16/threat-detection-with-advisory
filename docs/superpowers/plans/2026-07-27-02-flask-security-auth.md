# Plan 2: Flask Security Hardening & Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Depends on Plan 1** (`2026-07-27-01-db-backend-fix.md`) being complete — this plan assumes `DatabaseManager` has no connection leaks and `requirements.txt` exists.

**Goal:** Remove the hardcoded Flask secret key, disable debug mode and unsafe dev-server flags in production, restrict CORS, and add real session-based authentication (login/logout, password hashing) that protects every `/api/*` route using the existing (currently unused) `users` table in `schema.sql`.

**Architecture:** Flask's built-in session cookie mechanism (`flask.session`) backed by the `SECRET_KEY`, no external session store needed for a single-user/small-team desktop-adjacent tool. Passwords are hashed with `werkzeug.security.generate_password_hash` (already a Flask dependency, no new library needed). A `login_required` decorator wraps every existing route. A one-time `create_admin_user` CLI helper bootstraps the first account since there is no public registration endpoint (this is an internal security tool, not a multi-tenant SaaS).

**Tech Stack:** Flask, Flask-Login (session management) or hand-rolled session dict — this plan uses Flask's built-in `session` object directly to avoid adding another dependency, since the auth surface is small (one role, no permissions matrix).

---

## Context You Need

- `src/dashboard/app.py:36` currently has `app.config['SECRET_KEY'] = 'cybersecurity-threat-advisor-2026'` — hardcoded and committed to git history already, so even after removal, anyone with repo history access still has this old value. Document this in the commit message but do not attempt to rewrite git history (out of scope, high risk).
- `src/dashboard/app.py:37-38`: `CORS(app)` and `SocketIO(app, cors_allowed_origins="*")` — both wide open.
- `src/dashboard/app.py:492`: `socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)`.
- `config/config.yaml:110-116` already has a `dashboard:` section with `host: "127.0.0.1"` and `port: 5000` that is never read by `app.py` — this plan wires it up.
- `config/config.yaml:7-8` has `system.environment: "development"` and `system.debug: true` — these should drive whether Flask debug mode is on, not a hardcoded `True`.
- `schema.sql:3-10` already defines a `users` table: `id, username, email, password_hash, created_at, last_login` — reuse this exactly, do not redesign it.
- No registration endpoint will be added (avoids open sign-up on a security tool). A CLI script creates the first user.
- `python-dotenv` is not currently a dependency; this plan reads secrets from real OS environment variables (`os.environ`) to keep the dependency list small, and documents `.env` usage manually via `os.environ` + a documented shell-export step, since a `.env` loader is a nice-to-have, not required for correctness.

## File Structure

- Modify: `src/database/db_manager.py` — add `create_user`, `get_user_by_username`, `update_last_login` methods.
- Create: `src/auth.py` — password hashing helpers, `login_required` decorator, blueprint for `/login` and `/logout`.
- Modify: `src/dashboard/app.py` — remove hardcoded secret, read `SECRET_KEY` from env, restrict CORS, read debug/host/port from config, register auth blueprint, apply `login_required` to all routes and blueprints.
- Modify: `src/dashboard/routes/api_threats.py`, `api_stats.py`, `api_analytics.py`, `api_notifications.py`, `api_ml.py` — apply `login_required` decorator to every route.
- Create: `scripts/create_admin_user.py` — one-time CLI bootstrap script.
- Create: `templates/login.html` — minimal login form (the project already has a `templates/` dir per `render_template` calls in `app.py`).
- Create: `tests/test_auth.py` — unit tests for password hashing, login, and route protection.
- Modify: `.env.example` (create if missing) — documents `SECRET_KEY` env var requirement.

---

### Task 1: Add user-management methods to `DatabaseManager`

**Files:**
- Modify: `src/database/db_manager.py`
- Test: `tests/test_db_manager.py` (append)

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_db_manager.py` inside `TestDatabaseManager`:

```python
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
```

Add `import sqlite3` at the top of `tests/test_db_manager.py` if not already present (it is, from Task 3 of Plan 1's helper method — verify before adding a duplicate import).

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_db_manager.py::TestDatabaseManager::test_create_user_and_fetch_by_username -v`
Expected: FAIL with `AttributeError: 'DatabaseManager' object has no attribute 'create_user'`

- [ ] **Step 3: Add the three methods to `DatabaseManager`**

In `src/database/db_manager.py`, add these methods after `vacuum()` (the last method added in Plan 1 Task 4):

```python
    def create_user(self, username: str, email: str, password_hash: str) -> int:
        """
        Create a new user account.

        Args:
            username: Unique username
            email: Unique email address
            password_hash: Pre-hashed password (never store plaintext)

        Returns:
            ID of the created user

        Raises:
            sqlite3.IntegrityError: If username or email already exists
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
            ''', (username, email, password_hash))
            conn.commit()
            user_id = cursor.lastrowid
            self.logger.info(f"Created user: {username} (ID: {user_id})")
            return user_id
        finally:
            conn.close()

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a user by username.

        Args:
            username: Username to look up

        Returns:
            User dictionary or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def update_last_login(self, username: str):
        """
        Update a user's last_login timestamp to now.

        Args:
            username: Username to update
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?
            ''', (username,))
            conn.commit()
        finally:
            conn.close()

```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_db_manager.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/database/db_manager.py tests/test_db_manager.py
git commit -m "feat: add user management methods to DatabaseManager (create_user, get_user_by_username, update_last_login)"
```

---

### Task 2: Create `src/auth.py` with password hashing and `login_required` decorator

**Files:**
- Create: `src/auth.py`
- Test: `tests/test_auth.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.auth'`

- [ ] **Step 3: Create `src/auth.py`**

Create `e:\PROJECT\cybersecurity-threat-advisor\src\auth.py`:

```python
"""
Authentication helpers for the Flask dashboard.

Provides password hashing (via werkzeug, already a Flask dependency),
a login_required decorator backed by Flask's signed session cookie,
and no public registration endpoint by design — accounts are created
via scripts/create_admin_user.py.
"""

from functools import wraps

from flask import session, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password for storage. Never store plaintext passwords."""
    return generate_password_hash(plain_password)


def verify_password(password_hash: str, plain_password: str) -> bool:
    """Check a plaintext password against a stored hash."""
    return check_password_hash(password_hash, plain_password)


def login_required(view_func):
    """
    Decorator that redirects unauthenticated requests to /login.

    For JSON API routes (path starts with /api/), returns a 401 JSON
    response instead of a redirect, since a browser redirect makes no
    sense for a fetch()/XHR caller.
    """
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                from flask import jsonify
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)
    return wrapped
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/auth.py tests/test_auth.py
git commit -m "feat: add password hashing and login_required decorator"
```

---

### Task 3: Add `/login` and `/logout` routes to the dashboard

**Files:**
- Modify: `src/dashboard/app.py`
- Create: `templates/login.html`
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Check where `templates/` lives**

Run: `find . -maxdepth 2 -iname templates -type d 2>/dev/null || dir /s /b templates 2>nul`

Confirm the exact path (should be `templates/` at repo root, since `render_template('dashboard.html')` in `app.py` uses Flask's default template folder resolution relative to the app's root path — verify by checking `Flask(__name__)`'s implied root, which is `src/dashboard/`, so the actual templates folder is likely `src/dashboard/templates/`). Use whichever path this command reveals as the real templates directory for Step 2.

- [ ] **Step 2: Create the login template**

Create the login template at the path confirmed in Step 1 (assume `src/dashboard/templates/login.html` based on Flask's default `Flask(__name__)` root-path convention; adjust if Step 1 revealed a different location):

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Cybersecurity Threat Advisor</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .login-box { background: #1e293b; padding: 2rem; border-radius: 8px; width: 320px; }
        h1 { font-size: 1.25rem; margin-bottom: 1rem; }
        input { width: 100%; padding: 0.5rem; margin-bottom: 1rem; border-radius: 4px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; box-sizing: border-box; }
        button { width: 100%; padding: 0.6rem; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .error { color: #f87171; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>Threat Advisor Login</h1>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
```

- [ ] **Step 3: Add `/login` and `/logout` routes to `app.py`**

In `src/dashboard/app.py`, add these imports near the top (after the existing `from flask import ...` line):

```python
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
```

(This replaces the existing `from flask import Flask, render_template, jsonify, request` line — add `session, redirect, url_for`.)

Also add this import alongside the other `from src...` imports:

```python
from src.auth import login_required, verify_password
```

Then, immediately after the `# ==================== WEB ROUTES ====================` comment and before the `@app.route('/')` index route, insert:

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication handler"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        user = db.get_user_by_username(username)
        if user and verify_password(user['password_hash'], password):
            session['username'] = username
            db.update_last_login(username)
            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)

        return render_template('login.html', error='Invalid username or password'), 401

    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    """Log the current user out"""
    session.pop('username', None)
    return redirect(url_for('login'))
```

- [ ] **Step 4: Write a test for the login flow using the real Flask test client**

Add to `tests/test_auth.py`:

```python
class TestLoginRoute(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.remove(self.db_path)

        os.environ['SECRET_KEY'] = 'test-secret-key'
        os.environ['THREAT_DB_PATH'] = self.db_path

        # Import app fresh so it picks up the env vars set above
        import importlib
        import src.dashboard.app as app_module
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
```

Note: this test references `os.environ['THREAT_DB_PATH']`, which does not exist yet in `app.py` — it will be added in Task 4 (Step of that task reads the DB path from this env var for testability, falling back to the config file value). If Task 4 hasn't been done yet when running this test, it will fail; that's expected — proceed to Task 4 next, then return to verify this test passes.

- [ ] **Step 5: Commit (tests will be verified green after Task 4)**

```bash
git add src/dashboard/app.py src/dashboard/templates/login.html tests/test_auth.py
git commit -m "feat: add login/logout routes and login page template"
```

---

### Task 4: Remove hardcoded secret key, restrict CORS, disable debug mode by default, apply login_required globally

**Files:**
- Modify: `src/dashboard/app.py`
- Create: `.env.example`

- [ ] **Step 1: Replace the hardcoded secret key and CORS setup**

In `src/dashboard/app.py`, replace:

```python
# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersecurity-threat-advisor-2026'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
```

with:

```python
# Initialize Flask app
app = Flask(__name__)

secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if os.environ.get('FLASK_ENV') == 'testing' or app.config.get('TESTING'):
        secret_key = 'test-only-secret-key-not-for-production'
    else:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and set it: set SECRET_KEY=<value> (Windows) or export SECRET_KEY=<value> (Unix)."
        )
app.config['SECRET_KEY'] = secret_key

allowed_origins = os.environ.get('CORS_ALLOWED_ORIGINS', 'http://localhost:5000').split(',')
CORS(app, origins=allowed_origins)
socketio = SocketIO(app, cors_allowed_origins=allowed_origins)
```

- [ ] **Step 2: Read the DB path from an env var override (for test isolation) falling back to config**

In `src/dashboard/app.py`, find:

```python
db = DatabaseManager(config.get('database.path', 'data/db/threats.db'))
```

Replace with:

```python
db = DatabaseManager(os.environ.get('THREAT_DB_PATH') or config.get('database.path', 'data/db/threats.db'))
```

- [ ] **Step 3: Apply `login_required` to every web page route**

In `src/dashboard/app.py`, add the `@login_required` decorator immediately above each of these existing route decorators (between the `@app.route(...)` line and the `def ...` line — decorator order matters, `login_required` goes closest to the function):

```python
@app.route('/')
@login_required
def index():
```

```python
@app.route('/threats')
@login_required
def threats_page():
```

```python
@app.route('/analytics')
@login_required
def analytics_page():
```

```python
@app.route('/assistant')
@login_required
def assistant_page():
```

```python
@app.route('/settings')
@login_required
def settings_page():
```

- [ ] **Step 4: Apply `login_required` to every inline API route in `app.py`**

Apply the same pattern to: `get_stats`, `get_threats`, `get_threat_detail`, `get_system_metrics`, `get_threat_timeline`, `start_scan`, `get_monitoring_status`, `start_monitoring`, `stop_monitoring`, `assistant_chat`. For example:

```python
@app.route('/api/stats')
@login_required
def get_stats():
```

Repeat this same `@login_required` insertion for each of the remaining eight routes listed above, in the same style (decorator placed directly above `def`, below `@app.route`).

- [ ] **Step 5: Fix `assistant_chat`'s call to a non-existent method (found in original audit)**

While editing `assistant_chat`, also fix the bug where it calls `ai_assistant.process_query(user_message)` but `AIAssistant` only defines `answer_question`. Replace:

```python
        # Get AI response
        response = ai_assistant.process_query(user_message)
```

with:

```python
        # Get AI response
        response = ai_assistant.answer_question(user_message)
```

Verify this is the correct method name first:
Run: `grep -n "def " src/assistant/ai_assistant.py`
Expected output includes a line like `def answer_question(self, ...)`. If the actual method signature takes different/additional required arguments, adjust the call accordingly using the real signature shown by this grep.

- [ ] **Step 6: Read debug/host/port from config instead of hardcoding, and disable unsafe werkzeug flag by default**

Replace the `if __name__ == '__main__':` block at the bottom of `app.py`:

```python
if __name__ == '__main__':
    print("=" * 70)
    print("  Cybersecurity Threat Advisor - Web Dashboard")
    print("=" * 70)
    print(f"  Dashboard URL: http://localhost:5000")
    print(f"  Backend: Integrated monitoring system")
    print(f"  Real-time: WebSocket enabled")
    print("=" * 70)
    print()
    
    # Run Flask app with SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
```

with:

```python
if __name__ == '__main__':
    dashboard_host = config.get('dashboard.host', '127.0.0.1')
    dashboard_port = config.get('dashboard.port', 5000)
    debug_mode = config.get('system.debug', False) and config.get('system.environment') == 'development'

    print("=" * 70)
    print("  Cybersecurity Threat Advisor - Web Dashboard")
    print("=" * 70)
    print(f"  Dashboard URL: http://{dashboard_host}:{dashboard_port}")
    print(f"  Backend: Integrated monitoring system")
    print(f"  Real-time: WebSocket enabled")
    print(f"  Debug mode: {debug_mode}")
    print("=" * 70)
    print()

    socketio.run(app, host=dashboard_host, port=dashboard_port, debug=debug_mode)
```

Note: `allow_unsafe_werkzeug=True` is removed entirely — that flag exists specifically to bypass Werkzeug's production-use warning, and the right fix is to not run the dev server in production at all (document this in Task 6's README note), not to silence the warning.

- [ ] **Step 7: Create `.env.example` documenting required environment variables**

Create `e:\PROJECT\cybersecurity-threat-advisor\.env.example`:

```
# Copy this file to .env and fill in real values. Never commit .env itself.

# Required: Flask session signing key. Generate with:
#   python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=

# Optional: comma-separated list of origins allowed to call the API cross-origin.
# Defaults to http://localhost:5000 if unset.
CORS_ALLOWED_ORIGINS=http://localhost:5000

# Optional: override the SQLite database path (useful for tests).
# THREAT_DB_PATH=data/db/threats.db

# Notification credentials (see config/config.yaml notifications.smtp section)
# SMTP_SENDER_PASSWORD=
# TWILIO_AUTH_TOKEN=
```

- [ ] **Step 8: Verify `.env` is gitignored**

Run: `grep -n "^\.env$" .gitignore || grep -n "\.env" .gitignore`
Expected: some line matching `.env` exists. If not, append `.env` to `.gitignore`.

- [ ] **Step 9: Run the auth test suite with the now-complete env var wiring**

Run:
```bash
set SECRET_KEY=test-secret-for-local-run
python -m pytest tests/test_auth.py -v
```
(On Windows PowerShell use `$env:SECRET_KEY = "test-secret-for-local-run"` instead of `set`.)

Expected: All PASS, including the `TestLoginRoute` tests deferred from Task 3.

- [ ] **Step 10: Commit**

```bash
git add src/dashboard/app.py .env.example .gitignore
git commit -m "fix: remove hardcoded SECRET_KEY, restrict CORS, disable unsafe debug mode, protect all routes with login_required"
```

---

### Task 5: Apply `login_required` to all blueprint routes

**Files:**
- Modify: `src/dashboard/routes/api_threats.py`
- Modify: `src/dashboard/routes/api_stats.py`
- Modify: `src/dashboard/routes/api_analytics.py`
- Modify: `src/dashboard/routes/api_notifications.py`
- Modify: `src/dashboard/routes/api_ml.py`

- [ ] **Step 1: Add the import to each of the 5 route files**

In each of `api_threats.py`, `api_stats.py`, `api_analytics.py`, `api_notifications.py`, `api_ml.py`, add this import near the top (after the existing `from flask import ...` line):

```python
from src.auth import login_required
```

- [ ] **Step 2: Apply `@login_required` to every route in `api_threats.py`**

In `src/dashboard/routes/api_threats.py`, add `@login_required` directly below each `@threats_bp.route(...)` line, above each `def`:

```python
    @threats_bp.route('/', methods=['GET'])
    @login_required
    def get_threats():
```

```python
    @threats_bp.route('/<int:threat_id>', methods=['GET'])
    @login_required
    def get_threat_detail(threat_id):
```

```python
    @threats_bp.route('/<int:threat_id>/status', methods=['PUT'])
    @login_required
    def update_threat_status(threat_id):
```

```python
    @threats_bp.route('/critical', methods=['GET'])
    @login_required
    def get_critical_threats():
```

- [ ] **Step 3: Apply `@login_required` to every route in `api_stats.py`**

```python
    @stats_bp.route('/', methods=['GET'])
    @login_required
    def get_stats():
```

```python
    @stats_bp.route('/by-category', methods=['GET'])
    @login_required
    def get_stats_by_category():
```

```python
    @stats_bp.route('/by-severity', methods=['GET'])
    @login_required
    def get_stats_by_severity():
```

- [ ] **Step 4: Apply `@login_required` to every route in `api_analytics.py`**

```python
    @analytics_bp.route('/timeline', methods=['GET'])
    @login_required
    def get_threat_timeline():
```

```python
    @analytics_bp.route('/top-threats', methods=['GET'])
    @login_required
    def get_top_threats():
```

```python
    @analytics_bp.route('/detection-rate', methods=['GET'])
    @login_required
    def get_detection_rate():
```

- [ ] **Step 5: Apply `@login_required` to every route in `api_notifications.py`**

```python
    @notifications_bp.route('/status', methods=['GET'])
    @login_required
    def get_notification_status():
```

```python
    @notifications_bp.route('/recipients', methods=['GET'])
    @login_required
    def get_recipients():
```

```python
    @notifications_bp.route('/recipients', methods=['POST'])
    @login_required
    def add_recipient():
```

```python
    @notifications_bp.route('/recipients/<email>', methods=['DELETE'])
    @login_required
    def remove_recipient(email):
```

```python
    @notifications_bp.route('/test', methods=['POST'])
    @login_required
    def test_notification():
```

- [ ] **Step 6: Apply `@login_required` to every route in `api_ml.py`**

```python
    @ml_bp.route('/status', methods=['GET'])
    @login_required
    def get_ml_status():
```

```python
    @ml_bp.route('/train', methods=['POST'])
    @login_required
    def train_ml_model():
```

```python
    @ml_bp.route('/predict', methods=['POST'])
    @login_required
    def predict_anomaly():
```

- [ ] **Step 7: Write a test confirming a protected blueprint route rejects unauthenticated requests**

Add to `tests/test_auth.py`, inside a new test class:

```python
class TestBlueprintRoutesRequireAuth(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.remove(self.db_path)

        os.environ['SECRET_KEY'] = 'test-secret-key'
        os.environ['THREAT_DB_PATH'] = self.db_path

        import importlib
        import src.dashboard.app as app_module
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
```

- [ ] **Step 8: Run the tests**

Run:
```bash
set SECRET_KEY=test-secret-for-local-run
python -m pytest tests/test_auth.py -v
```
Expected: All PASS, including the 3 new `TestBlueprintRoutesRequireAuth` tests (they hit the JSON-401 branch of `login_required` since `/api/` paths are used).

- [ ] **Step 9: Commit**

```bash
git add src/dashboard/routes/api_threats.py src/dashboard/routes/api_stats.py src/dashboard/routes/api_analytics.py src/dashboard/routes/api_notifications.py src/dashboard/routes/api_ml.py tests/test_auth.py
git commit -m "feat: protect all API blueprint routes with login_required"
```

---

### Task 6: Create the admin-user bootstrap script

**Files:**
- Create: `scripts/create_admin_user.py`

- [ ] **Step 1: Create the scripts directory and the bootstrap script**

Create `e:\PROJECT\cybersecurity-threat-advisor\scripts\create_admin_user.py`:

```python
"""
One-time CLI script to create the first admin user account.

Usage:
    python scripts/create_admin_user.py <username> <email>

You will be prompted for a password (not shown on screen).
"""

import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.auth import hash_password
from src.database.db_manager import DatabaseManager
from src.utils import Config


def main():
    if len(sys.argv) != 3:
        print("Usage: python scripts/create_admin_user.py <username> <email>")
        sys.exit(1)

    username = sys.argv[1]
    email = sys.argv[2]

    password = getpass.getpass("Password: ")
    password_confirm = getpass.getpass("Confirm password: ")

    if password != password_confirm:
        print("Error: passwords do not match")
        sys.exit(1)

    if len(password) < 8:
        print("Error: password must be at least 8 characters")
        sys.exit(1)

    config = Config('config/config.yaml')
    db = DatabaseManager(config.get('database.path', 'data/db/threats.db'))

    existing = db.get_user_by_username(username)
    if existing:
        print(f"Error: user '{username}' already exists")
        sys.exit(1)

    user_id = db.create_user(username, email, hash_password(password))
    print(f"Created user '{username}' (ID: {user_id})")


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Verify the script runs (manual, requires interactive password entry)**

Run: `python scripts/create_admin_user.py testadmin testadmin@example.com`
When prompted, enter a test password twice. Expected output: `Created user 'testadmin' (ID: 1)`

Then clean up the test user for a real deployment:
Run:
```bash
python -c "
import sqlite3
conn = sqlite3.connect('data/db/threats.db')
conn.execute(\"DELETE FROM users WHERE username = 'testadmin'\")
conn.commit()
conn.close()
print('cleaned up test user')
"
```

- [ ] **Step 3: Commit**

```bash
git add scripts/create_admin_user.py
git commit -m "feat: add CLI script to bootstrap the first admin user account"
```

---

### Task 7: Run full test suite and update README with auth setup instructions

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the complete test suite**

Run:
```bash
set SECRET_KEY=test-secret-for-local-run
python -m pytest tests/ -v --tb=short 2>&1 | tail -100
```
Expected: `test_auth.py` and `test_db_manager.py` fully pass. No new failures introduced relative to the end of Plan 1.

- [ ] **Step 2: Add a "First-Time Setup" section to README.md documenting the new auth requirement**

In `README.md`, after the existing `## 📦 Installation` section's step 5 (`python main.py --init`), insert a new step:

```markdown
6. **Set up authentication (required to use the web dashboard):**
```bash
# Set a session secret key (required — the app will not start without this)
set SECRET_KEY=<paste output of the command below>
python -c "import secrets; print(secrets.token_hex(32))"

# Create your admin login
python scripts/create_admin_user.py <your-username> <your-email>
```
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document authentication setup in README"
```

---

## Plan Complete

This plan removes the hardcoded secret key, disables the unsafe Werkzeug dev-server flag, restricts CORS to configured origins, and adds real session-based authentication protecting every dashboard page and API route, backed by the previously-unused `users` table. ML/notification/detection correctness fixes are covered in **Plan 3**, and desktop app cleanup + remaining dead code removal in **Plan 4**.
