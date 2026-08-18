-- Audit log and scheduler tables

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    user_id TEXT,
    username TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT, -- JSON
    ip_address TEXT,
    user_agent TEXT,
    result TEXT NOT NULL DEFAULT 'success' -- 'success', 'failure', 'denied'
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_type, target_id);

CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    task_type TEXT NOT NULL, -- 'scan', 'report', 'cleanup', 'sync'
    cron_expression TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}', -- JSON task configuration
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run TEXT,
    next_run TEXT,
    last_status TEXT, -- 'success', 'failed', 'running'
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_schedules_enabled ON schedules(enabled);
CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    license_key TEXT NOT NULL UNIQUE,
    license_type TEXT NOT NULL,
    company_name TEXT,
    max_endpoints INTEGER,
    expires_at TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    issued_to TEXT,
    signature TEXT NOT NULL,
    valid INTEGER NOT NULL DEFAULT 0,
    activated_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    parameters TEXT NOT NULL DEFAULT '{}', -- JSON
    status TEXT NOT NULL DEFAULT 'pending',
    reason TEXT,
    issued_by TEXT,
    issued_at TEXT NOT NULL DEFAULT (datetime('now')),
    started_at TEXT,
    completed_at TEXT,
    result_message TEXT,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

CREATE INDEX IF NOT EXISTS idx_response_actions_endpoint ON response_actions(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status);
