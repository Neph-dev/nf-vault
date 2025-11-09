-- Rollback PostgreSQL-specific schema changes

DROP VIEW IF EXISTS active_devices;
DROP VIEW IF EXISTS recent_audit_logs;
DROP VIEW IF EXISTS expired_secrets;
DROP VIEW IF EXISTS active_secrets;

DROP TRIGGER IF EXISTS update_secrets_updated_at ON secrets;
DROP FUNCTION IF EXISTS update_updated_at_column();

DROP INDEX IF EXISTS idx_devices_registered_at;
DROP INDEX IF EXISTS idx_devices_trust_level;
DROP INDEX IF EXISTS idx_devices_is_active;
DROP INDEX IF EXISTS idx_devices_user_id;

DROP INDEX IF EXISTS idx_audit_logs_secret_id;
DROP INDEX IF EXISTS idx_audit_logs_operation;
DROP INDEX IF EXISTS idx_audit_logs_user_id;
DROP INDEX IF EXISTS idx_audit_logs_timestamp;

DROP INDEX IF EXISTS idx_secrets_expiry_date;
DROP INDEX IF EXISTS idx_secrets_created_at;
DROP INDEX IF EXISTS idx_secrets_category;
DROP INDEX IF EXISTS idx_secrets_scope;
DROP INDEX IF EXISTS idx_secrets_name;

DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS secrets;