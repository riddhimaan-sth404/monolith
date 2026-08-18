-- Migration 011: Create heartbeats table for telemetry health tracking
CREATE TABLE IF NOT EXISTS heartbeats (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    hostname TEXT,
    ip_address TEXT,
    agent_version TEXT,
    telemetry_state TEXT NOT NULL, -- 'healthy', 'blackout'
    signature_status TEXT NOT NULL -- 'valid', 'invalid'
);
