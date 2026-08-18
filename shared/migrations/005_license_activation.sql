-- License activation table for hardware-bound product key activation

CREATE TABLE IF NOT EXISTS activations (
    nonce TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    activated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_activations_fingerprint ON activations(fingerprint);
