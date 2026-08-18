-- Migration 007: Process and Hash Allowlist support
CREATE TABLE IF NOT EXISTS allowlist (
    id TEXT PRIMARY KEY,
    rule_type TEXT NOT NULL, -- 'hash_sha256', 'hash_md5', 'process_path', 'cmdline_pattern'
    value TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_allowlist_type_value ON allowlist(rule_type, value);
