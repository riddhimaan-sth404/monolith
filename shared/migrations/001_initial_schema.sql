-- Initial schema: core tables

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    mfa_secret TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    os_version TEXT NOT NULL,
    os_architecture TEXT,
    agent_version TEXT NOT NULL,
    driver_version TEXT,
    scanner_version TEXT,
    status TEXT NOT NULL DEFAULT 'offline',
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    policy_id TEXT,
    isolated INTEGER NOT NULL DEFAULT 0,
    isolation_policy TEXT,
    tags TEXT DEFAULT '[]',
    certificate_thumbprint TEXT,
    custom_fields TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
CREATE INDEX IF NOT EXISTS idx_endpoints_hostname ON endpoints(hostname);
CREATE INDEX IF NOT EXISTS idx_endpoints_policy ON endpoints(policy_id);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    collected_at TEXT NOT NULL DEFAULT (datetime('now')),
    sequence_number INTEGER NOT NULL DEFAULT 0,
    data TEXT NOT NULL, -- JSON payload
    hash TEXT,
    processed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

CREATE INDEX IF NOT EXISTS idx_events_endpoint ON events(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    event_id TEXT,
    rule_id TEXT,
    severity TEXT NOT NULL,
    confidence TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    title TEXT NOT NULL,
    description TEXT,
    mitre_technique_id TEXT,
    mitre_tactic TEXT,
    tags TEXT DEFAULT '[]',
    score REAL NOT NULL DEFAULT 0.0,
    suppressed INTEGER NOT NULL DEFAULT 0,
    process_info TEXT,
    file_info TEXT,
    registry_path TEXT,
    network_address TEXT,
    command_line TEXT,
    assigned_to TEXT,
    resolution_notes TEXT,
    acknowledged_at TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_endpoint ON alerts(endpoint_id);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    active INTEGER NOT NULL DEFAULT 1,
    rules TEXT NOT NULL DEFAULT '[]', -- JSON array of rules
    settings TEXT NOT NULL DEFAULT '{}', -- JSON object
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT,
    updated_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(active);

CREATE TABLE IF NOT EXISTS endpoint_policies (
    endpoint_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
    assigned_by TEXT,
    PRIMARY KEY (endpoint_id, policy_id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id),
    FOREIGN KEY (policy_id) REFERENCES policies(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL,
    refresh_token TEXT,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
