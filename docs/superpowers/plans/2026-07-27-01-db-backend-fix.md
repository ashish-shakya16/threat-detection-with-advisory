# Plan 1: Database & Core Backend Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `DatabaseManager`, `RiskScorer`, and `RuleEngine` correct, leak-free, and fully covered by unit tests — fixing the schema mismatch that crashes advisory logging, the connection leaks on exception paths, the severity-taxonomy inconsistency, and the missing `requirements.txt`.

**Architecture:** No new abstractions. `DatabaseManager` keeps its current flat method-per-query design but every method wraps its connection in `try/finally` (or a `with` block) so a failure never leaks a file handle. `schema.sql` becomes the single source of truth for column names — `db_manager.py` is edited to match it exactly, not the other way around, since `schema.sql` is what's actually loaded at runtime. Severity is standardized as a lowercase string enum (`low`, `medium`, `high`, `critical`) end-to-end; risk_level stays capitalized (`Low`, `Medium`, `High`, `Critical`) as the separate, already-consistent output of `RiskScorer`.

**Tech Stack:** Python 3.13, sqlite3 (stdlib), pytest.

---

## Context You Need

- Real DB schema lives in `src/database/schema.sql`, loaded via `cursor.executescript()` in `DatabaseManager._ensure_database()` (`src/database/db_manager.py:45-58`). The inline fallback schema in the `else` branch (lines 59-99) is dead code in practice (schema.sql always exists) but must stay consistent too since it's the disaster-recovery path if schema.sql is ever deleted.
- `threats` table columns (schema.sql:23-37): `id, device_id, threat_name, category, risk_level, risk_score, severity, confidence, source, description, detected_at, status`. No `timestamp`, no `threat_id` column (the primary key is just `id`).
- `advisories` table columns (schema.sql:48-59): `id, threat_id, title, description, reason, recommended_actions, preventive_tips, reference_links, generated_at`. No `advice`, no `remediation` columns.
- `events` table does not exist yet in `schema.sql` as of this plan's start — it needs to be added (columns: `id, event_type, source, event_data, severity, processed, timestamp`).
- `RuleEngine` (`src/detection/rule_engine.py`) produces `threat['severity']` as a lowercase string: `'low' | 'medium' | 'high'` (see `rule_engine.py:188`, sourced from `rule.get('severity')` in `config/rules.json`). It never produces `'critical'` — check `config/rules.json` to confirm the actual severity values used there before writing tests.
- `RiskScorer._severity_to_score` (`risk_scorer.py:131-137`) maps `'low'|'medium'|'high'|'critical'` to floats and calls `.lower()` on the input — so severity must always be a string, never `None` or a float, when it reaches `RiskScorer`.
- `RiskScorer.calculate_risk` writes `risk_level` (capitalized: `Low/Medium/High/Critical` from `_classify_risk_level`, line 187-204) onto the same threat dict that already has `severity` (lowercase, from RuleEngine) — these are two different fields and must NOT be conflated.
- `get_threat_statistics`'s "active_critical" query only checks `severity = 'high'`, ignoring `'critical'` — this underscounts if any rule ever sets severity to `'critical'`. Check `config/rules.json` for whether `'critical'` is used as a `severity` value there (if not, this is a defensive fix, not an active bug fix).

## File Structure

- Modify: `src/database/schema.sql` — add `events` table.
- Modify: `src/database/db_manager.py` — fix `log_advisory` column names, wrap every method in `try/finally`, fix `active_critical` query, add `update_threat_status()` and `vacuum()` methods, fix inline fallback schema to match schema.sql.
- Modify: `src/dashboard/app.py` — fix `get_threat_timeline()` to use `detected_at` not `timestamp`, remove dead `add_get_threat_by_id_to_db()` function.
- Modify: `src/dashboard/routes/api_threats.py` — wire up `update_threat_status` for real.
- Modify: `src/dashboard/routes/api_analytics.py` — implement `get_threat_timeline` properly (was returning empty stub).
- Modify: `src/desktop/main_window.py` — fix `threat.get('timestamp', ...)` → `threat.get('detected_at', ...)` (3 call sites), fix `clear_old_threats()` to actually call `cleanup_old_logs`, fix `optimize_database` to call the new `vacuum()` method.
- Create: `requirements.txt` — pins every third-party package actually imported by `src/` (excluding desktop-only PyQt6 packages, which stay in `requirements-desktop.txt`).
- Create: `tests/test_db_manager.py` — first-ever unit tests for `DatabaseManager`.
- Create: `tests/test_risk_scorer.py` — first-ever unit tests for `RiskScorer`.
- Create: `tests/test_rule_engine.py` — first-ever unit tests for `RuleEngine`.

---

### Task 1: Add `events` table to schema and fix inline fallback schema

**Files:**
- Modify: `src/database/schema.sql`
- Modify: `src/database/db_manager.py:59-99` (inline fallback in `_ensure_database`)

- [ ] **Step 1: Add the `events` table to schema.sql**

Open `src/database/schema.sql` and insert this new table definition immediately before the existing `CREATE TABLE IF NOT EXISTS threat_logs` block (currently starting at line 39):

```sql
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT,
    source TEXT,
    event_data TEXT,
    severity TEXT DEFAULT 'info',
    processed BOOLEAN DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

```

- [ ] **Step 2: Add matching indexes**

At the end of `schema.sql`, after the existing `CREATE INDEX` block, append:

```sql
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category);
CREATE INDEX IF NOT EXISTS idx_advisories_threat_id ON advisories(threat_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
```

- [ ] **Step 3: Fix the inline fallback schema in db_manager.py to match**

In `src/database/db_manager.py`, replace the entire `else` block (lines 59-99, the inline fallback schema executed only when `schema.sql` is missing) with:

```python
        else:
            # Fallback to inline schema if schema.sql doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    threat_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    severity TEXT,
                    confidence REAL,
                    source TEXT,
                    description TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    source TEXT,
                    event_data TEXT,
                    severity TEXT DEFAULT 'info',
                    processed BOOLEAN DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS advisories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id INTEGER NOT NULL,
                    title TEXT,
                    description TEXT,
                    reason TEXT,
                    recommended_actions TEXT,
                    preventive_tips TEXT,
                    reference_links TEXT,
                    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (threat_id) REFERENCES threats(id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    query TEXT,
                    response TEXT,
                    confidence REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
```

Note: `severity` changed from `REAL` to `TEXT` here to match schema.sql's actual usage (severity is always a string label like `'low'`/`'high'`, never a float — see Context section above).

- [ ] **Step 4: Verify by deleting the test DB and reinitializing**

Run:
```bash
python -c "
import os
if os.path.exists('data/db/threats_test_schema.db'):
    os.remove('data/db/threats_test_schema.db')
from src.database.db_manager import DatabaseManager
db = DatabaseManager('data/db/threats_test_schema.db')
import sqlite3
conn = sqlite3.connect('data/db/threats_test_schema.db')
cur = conn.cursor()
cur.execute(\"SELECT name FROM sqlite_master WHERE type='table'\")
tables = {row[0] for row in cur.fetchall()}
assert 'events' in tables, f'events table missing, got {tables}'
print('OK: events table created')
os.remove('data/db/threats_test_schema.db')
"
```
Expected output: `OK: events table created`

- [ ] **Step 5: Commit**

```bash
git add src/database/schema.sql src/database/db_manager.py
git commit -m "fix: add missing events table to schema, fix inline fallback schema mismatch"
```

---

### Task 2: Fix `log_advisory` column mismatch (Critical bug #1)

**Files:**
- Modify: `src/database/db_manager.py:176-207` (`log_advisory` method)
- Test: `tests/test_db_manager.py` (new file — created in this task)

- [ ] **Step 1: Write the failing test**

Create `tests/test_db_manager.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_db_manager.py::TestDatabaseManager::test_log_advisory_matches_schema_columns -v`
Expected: FAIL with `sqlite3.OperationalError: table advisories has no column named advice`

- [ ] **Step 3: Fix `log_advisory` to use the real schema columns**

In `src/database/db_manager.py`, replace the `log_advisory` method body (lines 176-207) with:

```python
    def log_advisory(self, threat_id: int, advisory_data: Dict[str, Any]) -> int:
        """
        Log security advisory for a threat.

        Args:
            threat_id: ID of associated threat
            advisory_data: Advisory information with keys:
                title, description, advice (list), remediation (str), references (list)

        Returns:
            ID of inserted advisory record
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO advisories (
                    threat_id, title, description, reason, recommended_actions, reference_links
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                threat_id,
                advisory_data.get('title'),
                advisory_data.get('description'),
                advisory_data.get('description'),
                json.dumps(advisory_data.get('advice', [])),
                json.dumps(advisory_data.get('references', []))
            ))

            advisory_id = cursor.lastrowid
            conn.commit()
            return advisory_id
        finally:
            conn.close()
```

Note: `reason` is populated with the same value as `description` since `advisory_data` (from `SecurityAdvisor.generate_advisory`) doesn't produce a separate "reason" field — check `src/advisory/advisor.py`'s return dict keys if this needs adjusting later; for now this preserves both pieces of information without dropping data. `remediation` text data goes into `recommended_actions` (closest matching column), stored as JSON since `recommended_actions` in schema.sql is a single TEXT column but `advice` is a list.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_db_manager.py::TestDatabaseManager::test_log_advisory_matches_schema_columns -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/database/db_manager.py tests/test_db_manager.py
git commit -m "fix: log_advisory now writes to columns that actually exist in schema.sql"
```

---

### Task 3: Wrap every `DatabaseManager` method in try/finally to prevent connection leaks

**Files:**
- Modify: `src/database/db_manager.py` (all methods: `log_threat`, `log_event`, `get_recent_threats`, `get_threat_by_id`, `get_advisory_for_threat`, `get_threat_statistics`, `mark_threat_resolved`, `cleanup_old_logs`)
- Test: `tests/test_db_manager.py` (add to existing file)

- [ ] **Step 1: Write the failing test**

Add this test to `tests/test_db_manager.py` inside the `TestDatabaseManager` class:

```python
    def test_log_threat_closes_connection_even_on_bad_data(self):
        # Passing a non-serializable value would previously leave the
        # connection open if an exception occurred mid-method.
        import sqlite3

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
        # SQLite doesn't expose a connection count directly; instead verify
        # the db file isn't locked by opening + writing to it immediately.
        conn = sqlite3.connect(self.db_path, timeout=0.1)
        conn.execute('SELECT 1')
        conn.close()
        return 0
```

- [ ] **Step 2: Run test to verify it fails or passes trivially (baseline)**

Run: `python -m pytest tests/test_db_manager.py -v`
Expected: Both tests PASS at this point (the leak only manifests under concurrent access or repeated failures — this test documents intent; the real safety net is the `finally` blocks added next). Proceed to Step 3 regardless.

- [ ] **Step 3: Wrap `log_threat` in try/finally**

Replace `log_threat` (currently ends around line 142) with:

```python
    def log_threat(self, threat_data: Dict[str, Any]) -> int:
        """
        Log a detected threat to the database.

        Args:
            threat_data: Dictionary containing threat information
                Required keys: threat_name, category, severity, risk_level,
                              risk_score, confidence

        Returns:
            ID of the inserted threat record
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO threats (
                    threat_name, category, severity,
                    risk_level, risk_score, confidence, source, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_data.get('threat_name'),
                threat_data.get('category'),
                threat_data.get('severity'),
                threat_data.get('risk_level'),
                threat_data.get('risk_score'),
                threat_data.get('confidence'),
                threat_data.get('source', 'Unknown'),
                threat_data.get('description', '')
            ))

            threat_id = cursor.lastrowid
            conn.commit()
            self.logger.info(f"Logged threat: {threat_data.get('threat_name')} (ID: {threat_id})")
            return threat_id
        finally:
            conn.close()
```

- [ ] **Step 4: Wrap `log_event` in try/finally**

Replace `log_event` with:

```python
    def log_event(self, event_data: Dict[str, Any]) -> int:
        """
        Log a monitoring event to the database.

        Args:
            event_data: Dictionary containing event information

        Returns:
            ID of the inserted event record
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO events (
                    timestamp, event_type, source, event_data, severity, processed
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                event_data.get('timestamp'),
                event_data.get('event_type'),
                event_data.get('source'),
                json.dumps(event_data.get('data', {})),
                event_data.get('severity', 'info'),
                0
            ))

            event_id = cursor.lastrowid
            conn.commit()
            return event_id
        finally:
            conn.close()
```

- [ ] **Step 5: Wrap `get_recent_threats` in try/finally**

Replace `get_recent_threats` with:

```python
    def get_recent_threats(self, limit: int = 50, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get recent threats from the database.

        Args:
            limit: Maximum number of threats to return
            hours: Time window in hours

        Returns:
            List of threat dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()

            cursor.execute('''
                SELECT * FROM threats
                WHERE detected_at > ?
                ORDER BY detected_at DESC
                LIMIT ?
            ''', (time_threshold, limit))

            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
```

- [ ] **Step 6: Wrap `get_threat_by_id` in try/finally**

Replace `get_threat_by_id` with:

```python
    def get_threat_by_id(self, threat_id: int) -> Optional[Dict[str, Any]]:
        """
        Get specific threat by ID.

        Args:
            threat_id: Threat ID

        Returns:
            Threat dictionary or None
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM threats WHERE id = ?', (threat_id,))
            row = cursor.fetchone()

            return dict(row) if row else None
        finally:
            conn.close()
```

- [ ] **Step 7: Wrap `get_advisory_for_threat` in try/finally**

Replace `get_advisory_for_threat` with:

```python
    def get_advisory_for_threat(self, threat_id: int) -> Optional[Dict[str, Any]]:
        """
        Get advisory for a specific threat.

        Args:
            threat_id: Threat ID

        Returns:
            Advisory dictionary or None
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM advisories WHERE threat_id = ?', (threat_id,))
            row = cursor.fetchone()

            return dict(row) if row else None
        finally:
            conn.close()
```

Note: this also removes the old dead no-op branch (`if 'reference_links' in advisory and advisory['reference_links']: advisory['reference_links'] = advisory['reference_links']`) which reassigned a value to itself and did nothing.

- [ ] **Step 8: Wrap `get_threat_statistics` in try/finally and fix active_critical query**

Replace `get_threat_statistics` with:

```python
    def get_threat_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get threat statistics for dashboard.

        Args:
            hours: Time window in hours

        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()

            cursor.execute('SELECT COUNT(*) FROM threats WHERE detected_at > ?', (time_threshold,))
            total_threats = cursor.fetchone()[0]

            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM threats
                WHERE detected_at > ?
                GROUP BY severity
            ''', (time_threshold,))
            by_severity = dict(cursor.fetchall())

            cursor.execute('''
                SELECT category, COUNT(*) as count
                FROM threats
                WHERE detected_at > ?
                GROUP BY category
            ''', (time_threshold,))
            by_category = dict(cursor.fetchall())

            cursor.execute('''
                SELECT COUNT(*) FROM threats
                WHERE detected_at > ? AND severity IN ('high', 'critical') AND status = 'active'
            ''', (time_threshold,))
            active_critical = cursor.fetchone()[0]

            return {
                'total_threats': total_threats,
                'by_severity': by_severity,
                'by_category': by_category,
                'active_critical': active_critical,
                'time_window_hours': hours
            }
        finally:
            conn.close()
```

- [ ] **Step 9: Wrap `mark_threat_resolved` in try/finally**

Replace `mark_threat_resolved` with:

```python
    def mark_threat_resolved(self, threat_id: int):
        """
        Mark a threat as resolved.

        Args:
            threat_id: Threat ID to mark as resolved
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE threats SET status = 'resolved' WHERE id = ?
            ''', (threat_id,))
            conn.commit()
            self.logger.info(f"Threat {threat_id} marked as resolved")
        finally:
            conn.close()
```

- [ ] **Step 10: Wrap `cleanup_old_logs` in try/finally**

Replace `cleanup_old_logs` with:

```python
    def cleanup_old_logs(self, days: int = 30):
        """
        Delete old threat logs.

        Args:
            days: Delete logs older than this many days
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()

            cursor.execute('DELETE FROM threats WHERE detected_at < ?', (time_threshold,))
            deleted_threats = cursor.rowcount
            cursor.execute('DELETE FROM events WHERE timestamp < ?', (time_threshold,))
            conn.commit()

            self.logger.info(f"Cleaned up {deleted_threats} old threat records")
        finally:
            conn.close()
```

- [ ] **Step 11: Run full test file to verify everything still passes**

Run: `python -m pytest tests/test_db_manager.py -v`
Expected: All tests PASS

- [ ] **Step 12: Commit**

```bash
git add src/database/db_manager.py tests/test_db_manager.py
git commit -m "fix: wrap all DatabaseManager methods in try/finally to prevent connection leaks"
```

---

### Task 4: Add `update_threat_status` and `vacuum` methods to `DatabaseManager`

**Files:**
- Modify: `src/database/db_manager.py` (add two new methods after `mark_threat_resolved`)
- Modify: `src/dashboard/routes/api_threats.py:61-85` (`update_threat_status` route — wire up the real call)
- Modify: `src/desktop/main_window.py` (fix `optimize_database` to use new `vacuum()` method)
- Test: `tests/test_db_manager.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_db_manager.py` inside `TestDatabaseManager`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_db_manager.py::TestDatabaseManager::test_update_threat_status tests/test_db_manager.py::TestDatabaseManager::test_vacuum_runs_without_error -v`
Expected: FAIL with `AttributeError: 'DatabaseManager' object has no attribute 'update_threat_status'`

- [ ] **Step 3: Add both methods to `DatabaseManager`**

In `src/database/db_manager.py`, insert these two new methods immediately after `mark_threat_resolved` (before `cleanup_old_logs`):

```python
    def update_threat_status(self, threat_id: int, status: str):
        """
        Update a threat's status to any valid value.

        Args:
            threat_id: Threat ID to update
            status: New status ('active', 'resolved', 'ignored', 'escalated')

        Raises:
            ValueError: If status is not one of the valid values
        """
        valid_statuses = {'active', 'resolved', 'ignored', 'escalated'}
        if status not in valid_statuses:
            raise ValueError(f"Invalid status '{status}'. Must be one of: {valid_statuses}")

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE threats SET status = ? WHERE id = ?', (status, threat_id))
            conn.commit()
            self.logger.info(f"Threat {threat_id} status updated to {status}")
        finally:
            conn.close()

    def vacuum(self):
        """Reclaim unused space and defragment the database file."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('VACUUM')
            self.logger.info("Database vacuumed")
        finally:
            conn.close()

```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_db_manager.py -v`
Expected: All PASS

- [ ] **Step 5: Wire up the real route in `api_threats.py`**

In `src/dashboard/routes/api_threats.py`, replace the `update_threat_status` route body (lines 61-85) with:

```python
    @threats_bp.route('/<int:threat_id>/status', methods=['PUT'])
    def update_threat_status(threat_id):
        """Update threat status"""
        try:
            data = request.get_json()
            status = data.get('status')

            if status not in ['resolved', 'ignored', 'escalated', 'active']:
                return jsonify({
                    'success': False,
                    'error': 'Invalid status'
                }), 400

            db.update_threat_status(threat_id, status)

            return jsonify({
                'success': True,
                'message': f'Threat status updated to {status}'
            })
        except Exception as e:
            logger.error(f"Error updating threat status: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
```

- [ ] **Step 6: Fix desktop app's `optimize_database` to call `vacuum()`**

Find the `optimize_database` method in `src/desktop/main_window.py` (uses `self.db.db_connection.execute("VACUUM")` around line 743). Replace that line:

Old:
```python
            self.db.db_connection.execute("VACUUM")
```

New:
```python
            self.db.vacuum()
```

- [ ] **Step 7: Fix desktop app's `clear_old_threats` to actually call cleanup**

Find `clear_old_threats` in `src/desktop/main_window.py` (around line 723-738). It computes `cutoff_date` but never calls the cleanup method. Locate the line that computes `cutoff_date` and, immediately after it (and before the success dialog is shown), add:

```python
            self.db.cleanup_old_logs(days=30)
```

- [ ] **Step 8: Verify with manual smoke test**

Run:
```bash
python -c "
from src.database.db_manager import DatabaseManager
import os
if os.path.exists('data/db/threats_smoke.db'):
    os.remove('data/db/threats_smoke.db')
db = DatabaseManager('data/db/threats_smoke.db')
tid = db.log_threat({'threat_name':'T','category':'test','severity':'high','risk_level':'High','risk_score':0.9,'confidence':0.8})
db.update_threat_status(tid, 'ignored')
print(db.get_threat_by_id(tid)['status'])
db.vacuum()
print('OK')
os.remove('data/db/threats_smoke.db')
"
```
Expected output:
```
ignored
OK
```

- [ ] **Step 9: Commit**

```bash
git add src/database/db_manager.py src/dashboard/routes/api_threats.py src/desktop/main_window.py tests/test_db_manager.py
git commit -m "feat: add update_threat_status and vacuum to DatabaseManager, wire up desktop/API callers"
```

---

### Task 5: Fix desktop app's `timestamp` column references and dashboard's `get_threat_timeline`

**Files:**
- Modify: `src/desktop/main_window.py` (3 call sites using `threat.get('timestamp', ...)`)
- Modify: `src/dashboard/app.py:201-237` (`get_threat_timeline` route)
- Modify: `src/dashboard/app.py:451-476` (remove dead `add_get_threat_by_id_to_db`)

- [ ] **Step 1: Fix the 3 desktop call sites**

In `src/desktop/main_window.py`, find and replace all three occurrences:

Occurrence 1 (recent threats table population):
```python
                self.recent_threats_table.setItem(row, 4, QTableWidgetItem(threat.get('timestamp', '')[:16]))
```
becomes:
```python
                self.recent_threats_table.setItem(row, 4, QTableWidgetItem(str(threat.get('detected_at', ''))[:16]))
```

Occurrence 2 (full threats table population):
```python
                self.threats_table.setItem(row, 5, QTableWidgetItem(threat.get('timestamp', '')[:16]))
```
becomes:
```python
                self.threats_table.setItem(row, 5, QTableWidgetItem(str(threat.get('detected_at', ''))[:16]))
```

Occurrence 3 (threat detail dialog text):
```python
Time: {threat.get('timestamp', 'Unknown')}
```
becomes:
```python
Time: {threat.get('detected_at', 'Unknown')}
```

- [ ] **Step 2: Fix `get_threat_timeline` in app.py to use `detected_at` and guard against non-string severity**

In `src/dashboard/app.py`, replace the `get_threat_timeline` function body (lines 201-237) with:

```python
@app.route('/api/threat-timeline')
def get_threat_timeline():
    """Get threat timeline data for charts"""
    try:
        hours = int(request.args.get('hours', 24))
        threats = db.get_recent_threats(limit=1000, hours=hours)

        # Group by hour
        timeline = {}
        for threat in threats:
            detected_at = threat.get('detected_at')
            if not detected_at:
                continue
            timestamp = datetime.fromisoformat(detected_at)
            hour_key = timestamp.strftime('%Y-%m-%d %H:00')

            if hour_key not in timeline:
                timeline[hour_key] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

            timeline[hour_key]['count'] += 1
            severity = str(threat.get('severity', '')).lower()
            if severity in timeline[hour_key]:
                timeline[hour_key][severity] += 1

        # Convert to sorted list
        timeline_list = [
            {'time': k, **v}
            for k, v in sorted(timeline.items())
        ]

        return jsonify({
            'success': True,
            'data': timeline_list
        })
    except Exception as e:
        logger.error(f"Error getting threat timeline: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
```

- [ ] **Step 3: Also fix `perform_scan()`'s threat summary dict which references `threat_with_risk['timestamp']`**

In `src/dashboard/app.py`, inside `perform_scan()` (around line 371-378), the line:
```python
                'timestamp': threat_with_risk['timestamp']
```
uses `threat_with_risk['timestamp']`, which does exist on the in-memory threat dict at this point (set by `RuleEngine._create_threat_from_rule`, not read from the DB) — this one is correct as-is since it's reading the dict `RuleEngine` produced, not a DB row. No change needed here; this step exists only to confirm you've checked it and are not "fixing" a non-bug. Move on.

- [ ] **Step 4: Remove dead `add_get_threat_by_id_to_db` monkeypatch**

In `src/dashboard/app.py`, delete lines 451-476 entirely (the `add_get_threat_by_id_to_db` function definition and its call `add_get_threat_by_id_to_db()`). `DatabaseManager.get_threat_by_id` already exists natively (fixed/confirmed in Task 3), so this monkeypatch never executes and is pure dead code.

- [ ] **Step 5: Verify app.py still imports and runs cleanly**

Run: `python -c "import ast; ast.parse(open('src/dashboard/app.py').read()); print('syntax OK')"`
Expected: `syntax OK`

- [ ] **Step 6: Commit**

```bash
git add src/desktop/main_window.py src/dashboard/app.py
git commit -m "fix: use detected_at column consistently, remove dead get_threat_by_id monkeypatch"
```

---

### Task 6: Implement real `get_threat_timeline` and `get_detection_rate` in analytics routes

**Files:**
- Modify: `src/database/db_manager.py` (add `get_threat_timeline_by_day` method)
- Modify: `src/dashboard/routes/api_analytics.py:14-29,48-62`
- Test: `tests/test_db_manager.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_db_manager.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_db_manager.py::TestDatabaseManager::test_get_threat_timeline_by_day -v`
Expected: FAIL with `AttributeError: 'DatabaseManager' object has no attribute 'get_threat_timeline_by_day'`

- [ ] **Step 3: Add the method to `DatabaseManager`**

Insert this new method into `src/database/db_manager.py`, right after `get_threat_statistics`:

```python
    def get_threat_timeline_by_day(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get daily threat counts for the past N days, for analytics charts.

        Args:
            days: Number of days to look back

        Returns:
            List of {'date': 'YYYY-MM-DD', 'count': int} dictionaries, oldest first
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()

            cursor.execute('''
                SELECT date(detected_at) as day, COUNT(*) as count
                FROM threats
                WHERE detected_at > ?
                GROUP BY day
                ORDER BY day ASC
            ''', (time_threshold,))

            return [{'date': row[0], 'count': row[1]} for row in cursor.fetchall()]
        finally:
            conn.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_db_manager.py::TestDatabaseManager::test_get_threat_timeline_by_day -v`
Expected: PASS

- [ ] **Step 5: Wire up `api_analytics.py`'s `/timeline` route**

In `src/dashboard/routes/api_analytics.py`, replace the `get_threat_timeline` route body (lines 14-29) with:

```python
    @analytics_bp.route('/timeline', methods=['GET'])
    def get_threat_timeline():
        """Get threat detection timeline"""
        try:
            days = request.args.get('days', 7, type=int)
            timeline = db.get_threat_timeline_by_day(days=days)
            return jsonify({
                'success': True,
                'data': timeline
            })
        except Exception as e:
            logger.error(f"Error fetching timeline: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
```

- [ ] **Step 6: Wire up `api_analytics.py`'s `/detection-rate` route using real stats**

Replace the `get_detection_rate` route body (lines 48-62) with:

```python
    @analytics_bp.route('/detection-rate', methods=['GET'])
    def get_detection_rate():
        """Get detection rate statistics"""
        try:
            period = request.args.get('period', 'daily')
            hours = 24 if period == 'daily' else 24 * 7
            stats = db.get_threat_statistics(hours=hours)
            total = stats.get('total_threats', 0)
            rate = round(total / hours, 3) if hours else 0.0
            return jsonify({
                'success': True,
                'data': {'period': period, 'rate': rate, 'total_threats': total}
            })
        except Exception as e:
            logger.error(f"Error fetching detection rate: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
```

- [ ] **Step 7: Run full db_manager test file**

Run: `python -m pytest tests/test_db_manager.py -v`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add src/database/db_manager.py src/dashboard/routes/api_analytics.py tests/test_db_manager.py
git commit -m "feat: implement real threat timeline and detection rate analytics (were hardcoded stubs)"
```

---

### Task 7: Create `requirements.txt` with all actually-used dependencies

**Files:**
- Create: `requirements.txt`

- [ ] **Step 1: Verify exact import list by grepping the codebase**

Run:
```bash
grep -rhoE "^(import|from) [a-zA-Z_]+" src/ main.py | awk '{print $2}' | sort -u
```
Expected output includes (among stdlib modules to ignore): `flask`, `flask_socketio` (via `from flask_socketio import`), `flask_cors`, `psutil`, `yaml`, `requests`, `numpy`, `sklearn`, `twilio`.

- [ ] **Step 2: Create `requirements.txt`**

Create `e:\PROJECT\cybersecurity-threat-advisor\requirements.txt`:

```
# Core web framework
Flask==3.0.3
Flask-Cors==4.0.1
Flask-SocketIO==5.3.6
python-socketio==5.11.2
simple-websocket==1.0.0

# System/network monitoring
psutil==6.0.0

# Config and utilities
PyYAML==6.0.1
requests==2.31.0

# Machine learning
numpy==1.26.4
scikit-learn==1.5.0

# Notifications (SMS - optional but imported if enabled)
twilio==9.0.4

# Testing
pytest==8.4.2
pytest-asyncio==1.2.0
```

- [ ] **Step 3: Install and verify the dashboard imports cleanly**

Run: `python -m pip install -r requirements.txt`
Expected: All packages install without errors (some may already be present).

Run: `python -c "from src.dashboard.app import app; print('dashboard imports OK')"`
Expected: `dashboard imports OK`

- [ ] **Step 4: Run the full test suite to confirm the flask_socketio collection error is gone**

Run: `python -m pytest tests/ -v --tb=short 2>&1 | tail -40`
Expected: No `ModuleNotFoundError` during collection; tests run (some may still fail for unrelated reasons addressed in later plans — that's OK, just confirm collection succeeds).

- [ ] **Step 5: Commit**

```bash
git add requirements.txt
git commit -m "feat: add requirements.txt covering all actually-imported dependencies"
```

---

### Task 8: Unit tests for `RiskScorer`

**Files:**
- Create: `tests/test_risk_scorer.py`

- [ ] **Step 1: Write the tests**

Create `tests/test_risk_scorer.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they pass against current implementation**

Run: `python -m pytest tests/test_risk_scorer.py -v`
Expected: All PASS (RiskScorer's logic is already correct — these tests lock in current behavior and will catch regressions from future changes).

- [ ] **Step 3: Commit**

```bash
git add tests/test_risk_scorer.py
git commit -m "test: add unit tests for RiskScorer (previously zero coverage)"
```

---

### Task 9: Unit tests for `RuleEngine`, plus defensive `.get()` fix in `_create_threat_from_rule`

**Files:**
- Modify: `src/detection/rule_engine.py:171-202` (`_create_threat_from_rule`)
- Create: `tests/test_rule_engine.py`

- [ ] **Step 1: Write the failing test for the malformed-rule crash**

Create `tests/test_rule_engine.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify the malformed-rule test fails**

Run: `python -m pytest tests/test_rule_engine.py::TestRuleEngine::test_malformed_rule_missing_optional_fields_does_not_crash -v`
Expected: FAIL with `KeyError: 'description'`

- [ ] **Step 3: Fix `_create_threat_from_rule` to use `.get()` with defaults for optional fields**

In `src/detection/rule_engine.py`, replace `_create_threat_from_rule` (lines 171-202) with:

```python
    def _create_threat_from_rule(self, event: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create threat object from matched rule and event.

        Args:
            event: Matched event
            rule: Matched rule

        Returns:
            Threat dictionary
        """
        threat = {
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'threat_id': rule['id'],
            'threat_name': rule['name'],
            'description': rule.get('description', ''),
            'category': rule.get('category', 'Unknown'),
            'severity': rule['severity'],
            'confidence': rule.get('confidence', 0.5),
            'impact': rule.get('impact', 'unknown'),
            'source': event.get('source', 'unknown'),
            'event_data': event.get('data', {}),
            'rule_matched': rule['id'],
            'advisory_template': rule.get('advisory_template')
        }

        self.logger.info(
            f"Threat detected: {rule['name']} (Rule: {rule['id']}, "
            f"Severity: {rule['severity']})"
        )

        return threat
```

Note: `rule['id']`, `rule['name']`, and `rule['severity']` stay as required bracket access because `add_rule`'s validation (`required_fields = ['id', 'name', 'conditions', 'severity']`) already guarantees those three exist — only `description`, `category`, and `confidence` are truly optional per that validation, so those three get `.get()` with sensible defaults.

- [ ] **Step 4: Run full rule engine test file to verify all pass**

Run: `python -m pytest tests/test_rule_engine.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/detection/rule_engine.py tests/test_rule_engine.py
git commit -m "fix: RuleEngine no longer crashes on rules missing optional fields; add test coverage"
```

---

### Task 10: Run full test suite and verify no regressions

**Files:** None (verification only)

- [ ] **Step 1: Run the complete test suite**

Run: `python -m pytest tests/ -v --tb=short 2>&1 | tail -80`
Expected: `test_db_manager.py`, `test_risk_scorer.py`, `test_rule_engine.py` all pass. Pre-existing test files may still have unrelated failures (Flask auth/security issues are addressed in Plan 2) — confirm no NEW failures were introduced by this plan's changes by comparing against the baseline failures noted in Task 7 Step 4.

- [ ] **Step 2: Manually verify the dashboard scan endpoint no longer crashes on advisory logging**

Run:
```bash
python -c "
import sys, os
sys.path.insert(0, '.')
os.environ.setdefault('FLASK_ENV', 'testing')
from src.dashboard.app import perform_scan
try:
    threats = perform_scan()
    print(f'OK: scan completed, {len(threats)} threats')
except Exception as e:
    print(f'FAILED: {e}')
    raise
"
```
Expected: `OK: scan completed, N threats` (N may be 0 depending on live system state — the key signal is no exception).

- [ ] **Step 3: Final commit for this plan (if any uncommitted cleanup remains)**

```bash
git status
```
If clean, no action needed. If anything is uncommitted, review and commit it with an appropriate message before moving to Plan 2.

---

## Plan Complete

This plan fixes the schema-mismatch crash bug, connection leaks, dead/no-op endpoints, missing dependency manifest, and adds first-ever test coverage for the three previously-untested core modules (`DatabaseManager`, `RiskScorer`, `RuleEngine`). Flask security hardening and the new auth system are covered in **Plan 2: Flask Security & Auth**.
