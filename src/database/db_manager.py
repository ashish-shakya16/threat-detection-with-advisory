"""
Database Manager for Cybersecurity Threat Advisor.

This module handles all database operations:
- SQLite database initialization
- Threat logging
- Query operations
- Data retrieval for dashboard

Database Schema:
- threats: Stores detected threats
- events: Stores monitoring events
- advisories: Stores advisory messages
"""

import sqlite3
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json


class DatabaseManager:
    """
    Manages SQLite database operations for threat storage and retrieval.
    
    Explanation:
    - Creates database tables if they don't exist
    - Provides methods to insert threats and events
    - Offers query methods for dashboard and reporting
    - Handles database connections safely
    """
    
    def __init__(self, db_path: str = "data/db/threats.db"):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.logger = logging.getLogger('CyberAdvisor.Database')
        self._ensure_database()
    
    def _ensure_database(self):
        """Create database and tables if they don't exist."""
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Load and execute schema.sql
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
                cursor.executescript(schema_sql)
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

        # Migrate existing databases created before occurrence tracking existed
        existing_columns = {row[1] for row in cursor.execute('PRAGMA table_info(threats)').fetchall()}
        if 'occurrence_count' not in existing_columns:
            cursor.execute('ALTER TABLE threats ADD COLUMN occurrence_count INTEGER DEFAULT 1')
        if 'last_seen_at' not in existing_columns:
            cursor.execute('ALTER TABLE threats ADD COLUMN last_seen_at TIMESTAMP')
            cursor.execute('UPDATE threats SET last_seen_at = detected_at WHERE last_seen_at IS NULL')

        conn.commit()
        conn.close()

        self.logger.info(f"Database initialized at {self.db_path}")

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
                    risk_level, risk_score, confidence, source, description,
                    last_seen_at, occurrence_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
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

    def find_active_recurring_threat(self, threat_name: str, source: str, within_minutes: int = 5) -> Optional[Dict[str, Any]]:
        """
        Find an active threat with the same name/source last seen within the
        given time window, so a repeat detection can be merged into it
        instead of creating a duplicate row.

        Args:
            threat_name: Threat name to match
            source: Threat source to match
            within_minutes: How recently the threat must have last fired to count as still ongoing

        Returns:
            The matching threat row, or None if no ongoing match exists
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # last_seen_at/detected_at are written via SQLite's CURRENT_TIMESTAMP,
            # which is UTC — compare against another UTC-based cutoff computed
            # in SQL rather than a Python datetime.now() (local time), which
            # would silently never match if the local timezone is ahead of UTC.
            cursor.execute('''
                SELECT * FROM threats
                WHERE threat_name = ? AND source = ? AND status = 'active'
                      AND last_seen_at > datetime('now', ?)
                ORDER BY last_seen_at DESC
                LIMIT 1
            ''', (threat_name, source, f'-{within_minutes} minutes'))

            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def bump_threat_occurrence(self, threat_id: int, risk_score: float, risk_level: str) -> None:
        """
        Record another occurrence of an already-logged, still-ongoing threat:
        bumps occurrence_count and last_seen_at, and refreshes the risk score
        so a worsening/improving condition is reflected without spawning a
        duplicate row.

        Args:
            threat_id: ID of the existing threat row to update
            risk_score: Latest risk score for this occurrence
            risk_level: Latest risk level for this occurrence
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE threats
                SET occurrence_count = occurrence_count + 1,
                    last_seen_at = CURRENT_TIMESTAMP,
                    risk_score = ?,
                    risk_level = ?
                WHERE id = ?
            ''', (risk_score, risk_level, threat_id))
            conn.commit()
        finally:
            conn.close()

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

    def log_conversation(self, user_id: int, query: str, response: str, confidence: float = 1.0) -> int:
        """
        Log an AI assistant conversation turn.

        Args:
            user_id: ID of the user who asked the question
            query: The user's question
            response: The assistant's response
            confidence: Confidence score of the response (0-1)

        Returns:
            ID of the inserted conversation record
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ai_conversations (user_id, query, response, confidence)
                VALUES (?, ?, ?, ?)
            ''', (user_id, query, response, confidence))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def get_conversations_for_user(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent conversation history for a user.

        Args:
            user_id: User ID to fetch conversations for
            limit: Maximum number of conversations to return

        Returns:
            List of conversation dictionaries, most recent first
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM ai_conversations
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            ''', (user_id, limit))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_system_info(self, rules_loaded: int = 0) -> Dict[str, Any]:
        """
        Get basic system info for the settings page.

        Args:
            rules_loaded: Number of detection rules currently loaded (caller-supplied,
                since DatabaseManager doesn't own rule loading)

        Returns:
            Dictionary with version, database_type, rules_loaded
        """
        return {
            'version': '1.2.0',
            'database_type': 'sqlite',
            'rules_loaded': rules_loaded,
        }

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
