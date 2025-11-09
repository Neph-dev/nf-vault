package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestPostgreSQLStore tests the PostgreSQL storage implementation.
// This test requires a running PostgreSQL instance.
func TestPostgreSQLStore(t *testing.T) {
	// Skip if PostgreSQL URL not provided
	dbURL := os.Getenv("POSTGRES_TEST_URL")
	if dbURL == "" {
		t.Skip("POSTGRES_TEST_URL not set, skipping PostgreSQL tests")
		return
	}

	// Create a temporary directory for test migrations
	migrationDir := createPostgresMigrations(t)
	defer os.RemoveAll(migrationDir)

	// Create PostgreSQL store
	store, err := NewPostgreSQLStore(dbURL, migrationDir)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("Ping", func(t *testing.T) {
		err := store.Ping(ctx)
		if err != nil {
			t.Errorf("Ping failed: %v", err)
		}
	})

	t.Run("SecretCRUD", func(t *testing.T) {
		testPostgresSecretCRUD(t, store)
	})

	t.Run("Stats", func(t *testing.T) {
		testPostgresStats(t, store)
	})
}

func testPostgresSecretCRUD(t *testing.T, store Store) {
	ctx := context.Background()

	// Test data
	secret := &Secret{
		ID:            uuid.New().String(),
		Name:          fmt.Sprintf("postgres-test-secret-%d", time.Now().UnixNano()),
		EncryptedKey:  []byte("encrypted-key-data"),
		EncryptedData: []byte("encrypted-secret-data"),
		Scope:         ScopeUser,
		Category:      CategoryPassword,
		Tags:          []string{"postgres", "test"},
		ExpiryDate:    nil,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Version:       1,
		Metadata:      map[string]string{"type": "test"},
	}

	// Test CreateSecret
	err := store.CreateSecret(ctx, secret)
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	// Test GetSecret
	retrieved, err := store.GetSecret(ctx, secret.Name)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	if retrieved.Name != secret.Name {
		t.Errorf("Expected name %s, got %s", secret.Name, retrieved.Name)
	}

	// Test SecretExists
	exists, err := store.SecretExists(ctx, secret.Name)
	if err != nil {
		t.Fatalf("SecretExists failed: %v", err)
	}
	if !exists {
		t.Error("Secret should exist")
	}

	// Test UpdateSecret
	secret.EncryptedData = []byte("updated-encrypted-data")
	err = store.UpdateSecret(ctx, secret)
	if err != nil {
		t.Fatalf("UpdateSecret failed: %v", err)
	}

	// Test ListSecrets
	secrets, err := store.ListSecrets(ctx, nil)
	if err != nil {
		t.Fatalf("ListSecrets failed: %v", err)
	}
	if len(secrets) == 0 {
		t.Error("Expected at least one secret")
	}

	// Test DeleteSecret
	err = store.DeleteSecret(ctx, secret.Name)
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}

	// Verify deletion
	_, err = store.GetSecret(ctx, secret.Name)
	if err == nil {
		t.Error("Expected error after deletion, got nil")
	}
}

func testPostgresStats(t *testing.T, store Store) {
	ctx := context.Background()

	// Test Stats
	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	if stats.Health != "healthy" {
		t.Errorf("Expected health to be 'healthy', got %s", stats.Health)
	}
}

func createPostgresMigrations(t *testing.T) string {
	tempDir := t.TempDir()
	migrationDir := filepath.Join(tempDir, "migrations")
	
	err := os.MkdirAll(migrationDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create migration directory: %v", err)
	}

	// Use the PostgreSQL migration files
	upSQL := `
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    encrypted_key BYTEA NOT NULL,
    encrypted_data BYTEA NOT NULL,
    scope TEXT NOT NULL DEFAULT 'user',
    category TEXT NOT NULL DEFAULT 'general',
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
    operation TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    client_ip INET,
    user_agent TEXT,
    operation_details JSONB DEFAULT '{}',
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    session_id TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    public_key TEXT,
    fingerprint TEXT,
    platform TEXT,
    app_version TEXT,
    last_used_at TIMESTAMP WITH TIME ZONE,
    registered_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    trust_level TEXT NOT NULL DEFAULT 'untrusted',
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
`

	downSQL := `
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS secrets;
`

	// Write migration files
	err = os.WriteFile(filepath.Join(migrationDir, "001_initial_schema.up.sql"), []byte(upSQL), 0644)
	if err != nil {
		t.Fatalf("Failed to write up migration: %v", err)
	}

	err = os.WriteFile(filepath.Join(migrationDir, "001_initial_schema.down.sql"), []byte(downSQL), 0644)
	if err != nil {
		t.Fatalf("Failed to write down migration: %v", err)
	}

	return migrationDir
}