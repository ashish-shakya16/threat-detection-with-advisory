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

        conn.commit()
        conn.close()

        self.logger.info(f"Database initialized at {self.db_path}")
    
    def log_threat(self, threat_data: Dict[str, Any]) -> int:
        """
        Log a detected threat to the database.
        
        Args:
            threat_data: Dictionary containing threat information
                Required keys: timestamp, threat_id, threat_name, category, 
                              severity, risk_level, risk_score, confidence
        
        Returns:
            ID of the inserted threat record
        """
        conn = sqlite3.connect(self.db_path)
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
        conn.close()
        
        self.logger.info(f"Logged threat: {threat_data.get('threat_name')} (ID: {threat_id})")
        return threat_id
    
    def log_event(self, event_data: Dict[str, Any]) -> int:
        """
        Log a monitoring event to the database.
        
        Args:
            event_data: Dictionary containing event information
        
        Returns:
            ID of the inserted event record
        """
        conn = sqlite3.connect(self.db_path)
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
        conn.close()
        
        return event_id
    
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
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute('''
            SELECT * FROM threats
            WHERE detected_at > ?
            ORDER BY detected_at DESC
            LIMIT ?
        ''', (time_threshold, limit))
        
        threats = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return threats
    
    def get_threat_by_id(self, threat_id: int) -> Optional[Dict[str, Any]]:
        """
        Get specific threat by ID.
        
        Args:
            threat_id: Threat ID
        
        Returns:
            Threat dictionary or None
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threats WHERE id = ?', (threat_id,))
        row = cursor.fetchone()
        
        conn.close()
        
        return dict(row) if row else None
    
    def get_advisory_for_threat(self, threat_id: int) -> Optional[Dict[str, Any]]:
        """
        Get advisory for a specific threat.
        
        Args:
            threat_id: Threat ID
        
        Returns:
            Advisory dictionary or None
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM advisories WHERE threat_id = ?', (threat_id,))
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            advisory = dict(row)
            # Handle reference_links field
            if 'reference_links' in advisory and advisory['reference_links']:
                advisory['reference_links'] = advisory['reference_links']
            return advisory
        return None
    
    def get_threat_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get threat statistics for dashboard.
        
        Args:
            hours: Time window in hours
        
        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        # Total threats
        cursor.execute('SELECT COUNT(*) FROM threats WHERE detected_at > ?', (time_threshold,))
        total_threats = cursor.fetchone()[0]

        # Threats by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM threats
            WHERE detected_at > ?
            GROUP BY severity
        ''', (time_threshold,))
        by_severity = dict(cursor.fetchall())

        # Threats by category
        cursor.execute('''
            SELECT category, COUNT(*) as count
            FROM threats
            WHERE detected_at > ?
            GROUP BY category
        ''', (time_threshold,))
        by_category = dict(cursor.fetchall())

        # Active threats (high severity)
        cursor.execute('''
            SELECT COUNT(*) FROM threats
            WHERE detected_at > ? AND severity = 'high' AND status = 'active'
        ''', (time_threshold,))
        active_critical = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_threats': total_threats,
            'by_severity': by_severity,
            'by_category': by_category,
            'active_critical': active_critical,
            'time_window_hours': hours
        }
    
    def mark_threat_resolved(self, threat_id: int):
        """
        Mark a threat as resolved.
        
        Args:
            threat_id: Threat ID to mark as resolved
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE threats SET status = 'resolved' WHERE id = ?
        ''', (threat_id,))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Threat {threat_id} marked as resolved")
    
    def cleanup_old_logs(self, days: int = 30):
        """
        Delete old threat logs.
        
        Args:
            days: Delete logs older than this many days
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
        
        cursor.execute('DELETE FROM threats WHERE detected_at < ?', (time_threshold,))
        cursor.execute('DELETE FROM events WHERE timestamp < ?', (time_threshold,))
        
        deleted_threats = cursor.rowcount
        conn.commit()
        conn.close()
        
        self.logger.info(f"Cleaned up {deleted_threats} old threat records")
