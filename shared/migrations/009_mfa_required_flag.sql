-- Migration 009: Add mfa_required column to users
ALTER TABLE users ADD COLUMN mfa_required INTEGER NOT NULL DEFAULT 0;
