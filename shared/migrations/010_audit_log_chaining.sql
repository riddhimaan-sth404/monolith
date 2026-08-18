-- Migration 010: Add cryptographic chaining columns to audit_logs
ALTER TABLE audit_logs ADD COLUMN hash TEXT;
ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT;
