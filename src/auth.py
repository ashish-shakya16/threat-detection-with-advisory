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
