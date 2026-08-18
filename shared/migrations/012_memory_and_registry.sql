-- Extend scan_results for memory scan tracking
ALTER TABLE scan_results ADD COLUMN pid INTEGER;
ALTER TABLE scan_results ADD COLUMN process_name TEXT;
ALTER TABLE scan_results ADD COLUMN base_address TEXT;       -- hex string (e.g. "0x7FF800000000")
ALTER TABLE scan_results ADD COLUMN memory_region_count INTEGER DEFAULT 0;

-- Per-region alert records
CREATE TABLE IF NOT EXISTS memory_alerts (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
    process_id INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    region_base TEXT NOT NULL,
    region_size INTEGER NOT NULL,
    matched_rules TEXT,           -- JSON array of matched YARA rule names
    yara_matches INTEGER NOT NULL DEFAULT 0,
    contains_pe INTEGER NOT NULL DEFAULT 0,
    verdict TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_memory_alerts_endpoint ON memory_alerts(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_memory_alerts_verdict   ON memory_alerts(verdict);

-- Registry tamper tracking
CREATE TABLE IF NOT EXISTS registry_tamper_events (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
    key_path TEXT NOT NULL,
    operation TEXT NOT NULL,   -- 'acl_modified' | 'value_changed' | 'key_deleted' | 'blocked_write'
    offending_pid INTEGER,
    offending_process TEXT,
    old_value TEXT,            -- JSON: previous value for value_changed events
    new_value TEXT,            -- JSON: attempted value
    blocked INTEGER NOT NULL DEFAULT 0,  -- 1 if kernel blocked it
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reg_tamper_endpoint ON registry_tamper_events(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_reg_tamper_key      ON registry_tamper_events(key_path);
