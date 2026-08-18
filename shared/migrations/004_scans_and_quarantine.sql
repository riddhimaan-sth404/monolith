-- Scan and quarantine tables

CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TEXT,
    completed_at TEXT,
    total_files INTEGER NOT NULL DEFAULT 0,
    scanned_files INTEGER NOT NULL DEFAULT 0,
    clean_files INTEGER NOT NULL DEFAULT 0,
    suspicious_files INTEGER NOT NULL DEFAULT 0,
    malicious_files INTEGER NOT NULL DEFAULT 0,
    quarantined_files INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    scan_speed REAL,
    details TEXT DEFAULT '[]', -- JSON array of threat details
    triggered_by TEXT, -- 'scheduled', 'manual', 'realtime'
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

CREATE INDEX IF NOT EXISTS idx_scan_results_endpoint ON scan_results(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);

CREATE TABLE IF NOT EXISTS quarantine_entries (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    original_path TEXT NOT NULL,
    original_name TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT,
    sha1 TEXT,
    md5 TEXT,
    quarantined_by TEXT NOT NULL, -- 'auto', 'manual', 'rule'
    quarantined_at TEXT NOT NULL DEFAULT (datetime('now')),
    restored_at TEXT,
    deleted_at TEXT,
    status TEXT NOT NULL DEFAULT 'quarantined', -- 'quarantined', 'restored', 'deleted'
    threat_name TEXT,
    detection_rule TEXT,
    notes TEXT,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

CREATE INDEX IF NOT EXISTS idx_quarantine_endpoint ON quarantine_entries(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_entries(status);
CREATE INDEX IF NOT EXISTS idx_quarantine_sha256 ON quarantine_entries(sha256);

CREATE TABLE IF NOT EXISTS agent_local_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS offline_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id TEXT NOT NULL,
    message_type TEXT NOT NULL,
    payload TEXT NOT NULL, -- JSON
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    priority INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_offline_queue_priority ON offline_queue(priority, created_at);
