"""Shared test setup.

The dashboard creates its database connection when src.dashboard.app is first
imported. Point it at a throwaway file before any test imports the app, so the
suite never reads or writes the real data/db/threats.db.
"""

import os
import tempfile

os.environ.setdefault('FLASK_ENV', 'testing')
_TEST_DB_DIR = tempfile.mkdtemp(prefix='securex-tests-')
os.environ.setdefault('THREAT_DB_PATH', os.path.join(_TEST_DB_DIR, 'threats.db'))
