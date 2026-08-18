-- Migration 008: Add token_hash and session index for revocation checks
ALTER TABLE sessions ADD COLUMN token_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
