-- Initial schema for nef-vault
-- Creates core tables for secrets management, audit logging, and device management

-- Secrets table: stores encrypted secrets with metadata
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,                    -- UUID for secret identification
    name TEXT NOT NULL UNIQUE,              -- Human-readable secret name (unique per vault)
    encrypted_key BLOB NOT NULL,            -- Encrypted data encryption key (DEK)
    encrypted_data BLOB NOT NULL,           -- Encrypted secret content
    scope TEXT NOT NULL DEFAULT 'user',     -- Access scope (user, system, shared)
    category TEXT NOT NULL DEFAULT 'general', -- Secret category (password, api_key, certificate, etc.)
    tags TEXT,                              -- JSON array of tags for organization
    expiry_date DATETIME,                   -- Optional expiration date
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1,     -- Version for optimistic locking
    metadata TEXT                           -- JSON metadata (size, mime_type, etc.)
);

-- Audit logs table: tracks all operations for security and compliance
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id TEXT,                         -- Reference to secrets.id (NULL for non-secret operations)
    operation TEXT NOT NULL,               -- Operation type (CREATE, READ, UPDATE, DELETE, LOGIN, etc.)
    user_id TEXT NOT NULL,                 -- User who performed the operation
    device_id TEXT NOT NULL,               -- Device from which operation was performed
    client_ip TEXT,                        -- Client IP address
    user_agent TEXT,                       -- User agent string
    operation_details TEXT,                -- JSON details about the operation
    success BOOLEAN NOT NULL DEFAULT TRUE, -- Whether operation succeeded
    error_message TEXT,                    -- Error message if operation failed
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    session_id TEXT                        -- Session identifier
);

-- Devices table: manages registered devices for multi-device access
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,                    -- Device ID (UUID)
    user_id TEXT NOT NULL,                 -- User who owns this device
    device_name TEXT NOT NULL,             -- Human-readable device name
    device_type TEXT NOT NULL DEFAULT 'unknown', -- Device type (mobile, desktop, web, cli)
    public_key TEXT,                       -- Device public key for encryption
    fingerprint TEXT,                      -- Device fingerprint for identification
    platform TEXT,                        -- Platform information (iOS, Android, Windows, etc.)
    app_version TEXT,                      -- Application version
    last_used_at DATETIME,                 -- Last time device was used
    registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE, -- Whether device is active
    trust_level TEXT NOT NULL DEFAULT 'untrusted', -- Device trust level
    metadata TEXT                          -- JSON metadata about device
);

-- Create indices for performance optimization

-- Secrets table indices
CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
CREATE INDEX IF NOT EXISTS idx_secrets_scope ON secrets(scope);
CREATE INDEX IF NOT EXISTS idx_secrets_category ON secrets(category);
CREATE INDEX IF NOT EXISTS idx_secrets_created_at ON secrets(created_at);
CREATE INDEX IF NOT EXISTS idx_secrets_expiry_date ON secrets(expiry_date) WHERE expiry_date IS NOT NULL;

-- Audit logs indices
CREATE INDEX IF NOT EXISTS idx_audit_logs_secret_id ON audit_logs(secret_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_device_id ON audit_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_session_id ON audit_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_success ON audit_logs(success);

-- Devices table indices
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(fingerprint);
CREATE INDEX IF NOT EXISTS idx_devices_last_used_at ON devices(last_used_at);
CREATE INDEX IF NOT EXISTS idx_devices_is_active ON devices(is_active);
CREATE INDEX IF NOT EXISTS idx_devices_trust_level ON devices(trust_level);

-- Foreign key constraints (for databases that support them)
-- Note: SQLite requires PRAGMA foreign_keys = ON to enforce these

-- Create triggers for updated_at timestamp maintenance
CREATE TRIGGER IF NOT EXISTS secrets_updated_at 
    AFTER UPDATE ON secrets
    FOR EACH ROW
BEGIN
    UPDATE secrets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Create views for common queries

-- Active secrets view (non-expired)
CREATE VIEW IF NOT EXISTS active_secrets AS
SELECT 
    id, name, scope, category, tags, 
    created_at, updated_at, version
FROM secrets 
WHERE expiry_date IS NULL OR expiry_date > CURRENT_TIMESTAMP;

-- Recent audit logs view (last 30 days)
CREATE VIEW IF NOT EXISTS recent_audit_logs AS
SELECT 
    id, secret_id, operation, user_id, device_id,
    operation_details, success, timestamp
FROM audit_logs 
WHERE timestamp > datetime('now', '-30 days')
ORDER BY timestamp DESC;

-- Active devices view
CREATE VIEW IF NOT EXISTS active_devices AS
SELECT 
    id, user_id, device_name, device_type, platform,
    last_used_at, registered_at, trust_level
FROM devices 
WHERE is_active = TRUE
ORDER BY last_used_at DESC;