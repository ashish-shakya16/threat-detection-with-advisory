"""Tamper-evident audit log.

Every security-relevant action (logins, configuration changes, threat status
changes, response approvals and executions, email activity) is recorded with
who performed it, what it targeted, when, and the outcome.

Entries form a hash chain: each entry stores the SHA-256 of its own content
plus the previous entry's hash. Editing or deleting a row breaks the chain,
which verify_chain() detects. This makes tampering evident; it does not stop
someone with write access to the database file from rebuilding the chain,
so the database file itself should still be protected.
"""

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger('securex')

GENESIS_HASH = '0' * 64
SENSITIVE_KEYS = ('password', 'secret', 'token', 'api_key', 'apikey', 'credential')


def _scrub(details: Any) -> Any:
    """Remove secret-looking fields before anything is written to the log."""
    if isinstance(details, dict):
        return {
            key: ('[redacted]' if any(word in str(key).lower() for word in SENSITIVE_KEYS) else _scrub(value))
            for key, value in details.items()
        }
    if isinstance(details, list):
        return [_scrub(item) for item in details]
    return details


def _entry_hash(prev_hash: str, fields: Dict[str, Any]) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256((prev_hash + canonical).encode('utf-8')).hexdigest()


class AuditLog:
    """Append-only audit trail stored in the SecureX SQLite database."""

    HASHED_FIELDS = ('created_at', 'actor', 'action', 'target_type', 'target_id', 'outcome', 'details', 'source_ip')

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def record(self, actor: str, action: str, target_type: str = '', target_id: Any = '',
               outcome: str = 'success', details: Optional[Dict[str, Any]] = None,
               source_ip: str = '') -> Optional[int]:
        """Append an entry. Never raises: auditing must not break the caller."""
        fields = {
            'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f'),
            'actor': str(actor or 'system')[:100],
            'action': str(action)[:100],
            'target_type': str(target_type or '')[:50],
            'target_id': str(target_id if target_id is not None else '')[:100],
            'outcome': str(outcome)[:30],
            'details': json.dumps(_scrub(details or {}), sort_keys=True, default=str)[:4000],
            'source_ip': str(source_ip or '')[:64],
        }
        conn = self._connect()
        try:
            # IMMEDIATE takes the write lock before reading the chain head, so
            # concurrent writers cannot fork the chain.
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1').fetchone()
            prev_hash = row['entry_hash'] if row else GENESIS_HASH
            entry_hash = _entry_hash(prev_hash, fields)
            cursor = conn.execute(
                'INSERT INTO audit_log (created_at, actor, action, target_type, target_id, outcome, '
                'details, source_ip, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (*[fields[name] for name in self.HASHED_FIELDS], prev_hash, entry_hash),
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as error:
            conn.rollback()
            logger.error('Failed to write audit log entry %s: %s', action, error)
            return None
        finally:
            conn.close()

    def list(self, limit: int = 50, offset: int = 0, action: str = '', actor: str = '') -> Dict[str, Any]:
        clauses, params = [], []
        if action:
            clauses.append('action LIKE ?')
            params.append(f'{action}%')
        if actor:
            clauses.append('actor = ?')
            params.append(actor)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
        conn = self._connect()
        try:
            total = conn.execute(f'SELECT COUNT(*) FROM audit_log {where}', params).fetchone()[0]
            rows = conn.execute(
                f'SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ? OFFSET ?',
                (*params, limit, offset),
            ).fetchall()
        finally:
            conn.close()
        entries = []
        for row in rows:
            entry = dict(row)
            try:
                entry['details'] = json.loads(entry['details'] or '{}')
            except ValueError:
                pass
            entries.append(entry)
        return {'entries': entries, 'total': total}

    def verify_chain(self) -> Dict[str, Any]:
        """Recompute every hash and report the first entry that does not match."""
        conn = self._connect()
        try:
            rows = conn.execute('SELECT * FROM audit_log ORDER BY id ASC').fetchall()
        finally:
            conn.close()
        prev_hash = GENESIS_HASH
        for row in rows:
            fields = {name: row[name] for name in self.HASHED_FIELDS}
            if row['prev_hash'] != prev_hash or _entry_hash(prev_hash, fields) != row['entry_hash']:
                return {'valid': False, 'checked': len(rows), 'first_invalid_id': row['id']}
            prev_hash = row['entry_hash']
        return {'valid': True, 'checked': len(rows), 'first_invalid_id': None}
