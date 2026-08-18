-- IOC and Rules tables

CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence TEXT NOT NULL DEFAULT 'medium',
    description TEXT,
    source TEXT,
    reference TEXT,
    tags TEXT DEFAULT '[]',
    mitre_technique_id TEXT,
    mitre_tactic TEXT,
    malware_family TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_expires ON iocs(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(ioc_type, value);

CREATE TABLE IF NOT EXISTS ioc_comments (
    id TEXT PRIMARY KEY,
    ioc_id TEXT NOT NULL,
    text TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_comments_ioc ON ioc_comments(ioc_id);

CREATE TABLE IF NOT EXISTS yara_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    author TEXT,
    content TEXT NOT NULL,
    compiled BLOB,
    enabled INTEGER NOT NULL DEFAULT 1,
    mitre_technique_ids TEXT DEFAULT '[]',
    tags TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_yara_rules_enabled ON yara_rules(enabled);

CREATE TABLE IF NOT EXISTS sigma_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    author TEXT,
    content TEXT NOT NULL, -- YAML content
    compiled_rules TEXT, -- Converted conditions
    enabled INTEGER NOT NULL DEFAULT 1,
    log_sources TEXT DEFAULT '[]',
    mitre_technique_ids TEXT DEFAULT '[]',
    tags TEXT DEFAULT '[]',
    level TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sigma_rules_enabled ON sigma_rules(enabled);

CREATE TABLE IF NOT EXISTS detection_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    rule_type TEXT NOT NULL, -- 'ioc', 'yara', 'sigma', 'behavioral', 'compound'
    conditions TEXT NOT NULL, -- JSON rule conditions
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence TEXT NOT NULL DEFAULT 'medium',
    enabled INTEGER NOT NULL DEFAULT 1,
    mitre_technique_ids TEXT DEFAULT '[]',
    tags TEXT DEFAULT '[]',
    suppression_keys TEXT DEFAULT '[]',
    response_actions TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_detection_rules_type ON detection_rules(rule_type);

CREATE TABLE IF NOT EXISTS ioc_cache (
    endpoint_id TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (endpoint_id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);
