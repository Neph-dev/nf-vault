-- Rollback script for initial schema
-- Drops all tables, indices, triggers, and views created in 001_initial_schema.up.sql

-- Drop views first (they depend on tables)
DROP VIEW IF EXISTS active_devices;
DROP VIEW IF EXISTS recent_audit_logs;
DROP VIEW IF EXISTS active_secrets;

-- Drop triggers
DROP TRIGGER IF EXISTS secrets_updated_at;

-- Drop indices
DROP INDEX IF EXISTS idx_devices_trust_level;
DROP INDEX IF EXISTS idx_devices_is_active;
DROP INDEX IF EXISTS idx_devices_last_used_at;
DROP INDEX IF EXISTS idx_devices_fingerprint;
DROP INDEX IF EXISTS idx_devices_user_id;

DROP INDEX IF EXISTS idx_audit_logs_success;
DROP INDEX IF EXISTS idx_audit_logs_session_id;
DROP INDEX IF EXISTS idx_audit_logs_timestamp;
DROP INDEX IF EXISTS idx_audit_logs_operation;
DROP INDEX IF EXISTS idx_audit_logs_device_id;
DROP INDEX IF EXISTS idx_audit_logs_user_id;
DROP INDEX IF EXISTS idx_audit_logs_secret_id;

DROP INDEX IF EXISTS idx_secrets_expiry_date;
DROP INDEX IF EXISTS idx_secrets_created_at;
DROP INDEX IF EXISTS idx_secrets_category;
DROP INDEX IF EXISTS idx_secrets_scope;
DROP INDEX IF EXISTS idx_secrets_name;

-- Drop tables (order matters due to potential foreign key constraints)
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS secrets;