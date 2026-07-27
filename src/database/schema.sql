-- SecureX Database Schema

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_name TEXT NOT NULL,
    os_type TEXT,
    os_version TEXT,
    last_seen TIMESTAMP,
    status TEXT DEFAULT 'active',
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    threat_name TEXT NOT NULL,
    category TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score REAL NOT NULL,
    severity REAL,
    confidence REAL,
    source TEXT,
    description TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active',
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS threat_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER NOT NULL,
    event_type TEXT,
    event_data TEXT,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

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
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    scan_type TEXT,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    threats_found INTEGER DEFAULT 0,
    status TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    pid INTEGER,
    name TEXT,
    cpu_usage REAL,
    memory_usage REAL,
    status TEXT,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS network_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    source_ip TEXT,
    dest_ip TEXT,
    port INTEGER,
    protocol TEXT,
    status TEXT,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    query TEXT,
    response TEXT,
    confidence REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    threat_id INTEGER,
    title TEXT,
    message TEXT,
    is_read BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    report_type TEXT,
    period TEXT,
    total_threats INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_path TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    setting_key TEXT,
    setting_value TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_threats_device ON threats(device_id);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at);
CREATE INDEX IF NOT EXISTS idx_threats_risk_level ON threats(risk_level);
CREATE INDEX IF NOT EXISTS idx_scan_history_device ON scan_history(device_id);
CREATE INDEX IF NOT EXISTS idx_network_logs_device ON network_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_notifications_device ON notifications(device_id);
