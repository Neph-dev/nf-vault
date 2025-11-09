-- PostgreSQL version of the database schema
-- Uses PostgreSQL-specific features like JSONB and more advanced constraints

CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    encrypted_key BYTEA NOT NULL,
    encrypted_data BYTEA NOT NULL,
    scope TEXT NOT NULL DEFAULT 'user' CHECK (scope IN ('user', 'system')),
    category TEXT NOT NULL DEFAULT 'general' CHECK (category IN ('password', 'api_key', 'note', 'certificate', 'general')),
    tags JSONB DEFAULT '[]',
    expiry_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    version INTEGER NOT NULL DEFAULT 1,
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    secret_id TEXT,
    operation TEXT NOT NULL CHECK (operation IN ('create_secret', 'read_secret', 'update_secret', 'delete_secret', 'login', 'logout', 'register_device', 'deactivate_device')),
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    client_ip INET,
    user_agent TEXT,
    operation_details JSONB DEFAULT '{}',
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    session_id TEXT,
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL DEFAULT 'unknown' CHECK (device_type IN ('desktop', 'mobile', 'server', 'unknown')),
    public_key TEXT,
    fingerprint TEXT,
    platform TEXT,
    app_version TEXT,
    last_used_at TIMESTAMP WITH TIME ZONE,
    registered_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    trust_level TEXT NOT NULL DEFAULT 'untrusted' CHECK (trust_level IN ('untrusted', 'basic', 'trusted', 'full')),
    metadata JSONB DEFAULT '{}'
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
CREATE INDEX IF NOT EXISTS idx_secrets_scope ON secrets(scope);
CREATE INDEX IF NOT EXISTS idx_secrets_category ON secrets(category);
CREATE INDEX IF NOT EXISTS idx_secrets_created_at ON secrets(created_at);
CREATE INDEX IF NOT EXISTS idx_secrets_expiry_date ON secrets(expiry_date) WHERE expiry_date IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation);
CREATE INDEX IF NOT EXISTS idx_audit_logs_secret_id ON audit_logs(secret_id) WHERE secret_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_is_active ON devices(is_active);
CREATE INDEX IF NOT EXISTS idx_devices_trust_level ON devices(trust_level);
CREATE INDEX IF NOT EXISTS idx_devices_registered_at ON devices(registered_at);

-- Triggers for automatic updated_at handling
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_secrets_updated_at 
    BEFORE UPDATE ON secrets 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Views for common queries
CREATE OR REPLACE VIEW active_secrets AS
SELECT * FROM secrets 
WHERE expiry_date IS NULL OR expiry_date > NOW();

CREATE OR REPLACE VIEW expired_secrets AS
SELECT * FROM secrets 
WHERE expiry_date IS NOT NULL AND expiry_date <= NOW();

CREATE OR REPLACE VIEW recent_audit_logs AS
SELECT * FROM audit_logs 
WHERE timestamp >= NOW() - INTERVAL '30 days'
ORDER BY timestamp DESC;

CREATE OR REPLACE VIEW active_devices AS
SELECT * FROM devices 
WHERE is_active = TRUE
ORDER BY last_used_at DESC NULLS LAST;