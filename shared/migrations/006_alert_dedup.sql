-- Migration 006: Add hit_count to alerts for deduplication support
ALTER TABLE alerts ADD COLUMN hit_count INTEGER NOT NULL DEFAULT 1;
