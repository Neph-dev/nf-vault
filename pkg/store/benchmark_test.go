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

// BenchmarkSQLiteStore benchmarks the SQLite storage implementation.
func BenchmarkSQLiteStore(b *testing.B) {
	// Create a temporary directory for test migrations
	migrationDir := createBenchmarkMigrations(b)
	defer os.RemoveAll(migrationDir)

	// Create in-memory SQLite store
	store, err := NewSQLiteStore(":memory:", migrationDir)
	if err != nil {
		b.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	b.Run("CreateSecret", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			secret := &Secret{
				ID:            uuid.New().String(),
				Name:          fmt.Sprintf("benchmark-secret-%d", i),
				EncryptedKey:  []byte("benchmark-key"),
				EncryptedData: []byte("benchmark-data"),
				Scope:         ScopeUser,
				Category:      CategoryPassword,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
				Version:       1,
			}
			store.CreateSecret(ctx, secret)
		}
	})

	// Create some secrets for read benchmarks
	for i := 0; i < 1000; i++ {
		secret := &Secret{
			ID:            uuid.New().String(),
			Name:          fmt.Sprintf("read-benchmark-secret-%d", i),
			EncryptedKey:  []byte("benchmark-key"),
			EncryptedData: []byte("benchmark-data"),
			Scope:         ScopeUser,
			Category:      CategoryPassword,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Version:       1,
		}
		store.CreateSecret(ctx, secret)
	}

	b.Run("GetSecret", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			secretName := fmt.Sprintf("read-benchmark-secret-%d", i%1000)
			store.GetSecret(ctx, secretName)
		}
	})

	b.Run("ListSecrets", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			store.ListSecrets(ctx, nil)
		}
	})
}

func createBenchmarkMigrations(b *testing.B) string {
	tempDir := b.TempDir()
	migrationDir := filepath.Join(tempDir, "migrations")
	
	err := os.MkdirAll(migrationDir, 0755)
	if err != nil {
		b.Fatalf("Failed to create migration directory: %v", err)
	}

	// Copy migration files to temp directory
	upSQL := `
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    encrypted_key BLOB NOT NULL,
    encrypted_data BLOB NOT NULL,
    scope TEXT NOT NULL DEFAULT 'user',
    category TEXT NOT NULL DEFAULT 'general',
    tags TEXT,
    expiry_date DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id TEXT,
    operation TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    client_ip TEXT,
    user_agent TEXT,
    operation_details TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
    last_used_at DATETIME,
    registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    trust_level TEXT NOT NULL DEFAULT 'untrusted',
    metadata TEXT
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
		b.Fatalf("Failed to write up migration: %v", err)
	}

	err = os.WriteFile(filepath.Join(migrationDir, "001_initial_schema.down.sql"), []byte(downSQL), 0644)
	if err != nil {
		b.Fatalf("Failed to write down migration: %v", err)
	}

	return migrationDir
}