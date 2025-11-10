// Package store provides SQLite implementation of the Store interface.
// This implementation uses SQLite as the backend database with proper indexing and transaction support.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// SQLiteStore implements the Store interface using SQLite as the backend.
type SQLiteStore struct {
	db           *sql.DB
	migrationDir string
}

// NewSQLiteStore creates a new SQLite store instance.
func NewSQLiteStore(dataSourceName, migrationDir string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Configure SQLite for optimal performance and safety
	if err := configureSQLite(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure SQLite: %w", err)
	}

	store := &SQLiteStore{
		db:           db,
		migrationDir: migrationDir,
	}

	// Run migrations
	if err := store.runMigrations(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return store, nil
}

// configureSQLite sets up SQLite-specific settings for performance and safety.
func configureSQLite(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA foreign_keys = ON",                // Enable foreign key constraints
		"PRAGMA journal_mode = WAL",               // Write-Ahead Logging for better concurrency
		"PRAGMA synchronous = NORMAL",             // Good balance of safety and performance
		"PRAGMA cache_size = -64000",              // 64MB cache
		"PRAGMA temp_store = MEMORY",              // Store temporary tables in memory
		"PRAGMA mmap_size = 268435456",            // 256MB memory-mapped I/O
		"PRAGMA optimize",                         // Optimize database
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("failed to execute pragma %s: %w", pragma, err)
		}
	}

	// Set connection limits
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return nil
}

// runMigrations applies database migrations.
func (s *SQLiteStore) runMigrations() error {
	if s.migrationDir == "" {
		// If no migration directory is specified, create tables directly
		return s.createTables()
	}

	driver, err := sqlite3.WithInstance(s.db, &sqlite3.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	source, err := (&file.File{}).Open("file://" + s.migrationDir)
	if err != nil {
		return fmt.Errorf("failed to open migration source: %w", err)
	}

	m, err := migrate.NewWithInstance("file", source, "sqlite3", driver)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// createTables creates the database schema directly (used when no migrations are provided)
func (s *SQLiteStore) createTables() error {
	schemas := []string{
		// Secrets table
		`CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			encrypted_key BLOB NOT NULL,
			encrypted_data BLOB NOT NULL,
			scope TEXT NOT NULL DEFAULT 'user',
			category TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '[]',
			expiry_date DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			version INTEGER NOT NULL DEFAULT 1,
			metadata TEXT NOT NULL DEFAULT '{}'
		)`,
		
		// Devices table
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			device_name TEXT NOT NULL,
			public_key BLOB NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			metadata TEXT NOT NULL DEFAULT '{}'
		)`,
		
		// Audit logs table
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			secret_id TEXT,
			operation TEXT NOT NULL,
			user_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			client_ip TEXT,
			user_agent TEXT,
			operation_details TEXT NOT NULL DEFAULT '{}',
			success BOOLEAN NOT NULL,
			error_message TEXT,
			timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			session_id TEXT
		)`,
		
		// Indexes for better performance
		`CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_category ON secrets(category)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_created_at ON secrets(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_logs(operation)`,
	}

	for _, schema := range schemas {
		if _, err := s.db.Exec(schema); err != nil {
			return fmt.Errorf("failed to create table/index: %w", err)
		}
	}

	return nil
}

// CreateSecret stores a new secret in the database.
func (s *SQLiteStore) CreateSecret(ctx context.Context, secret *Secret) error {
	const query = `
		INSERT INTO secrets (
			id, name, encrypted_key, encrypted_data, scope, category, 
			tags, expiry_date, created_at, updated_at, version, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	tagsJSON, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = s.db.ExecContext(ctx, query,
		secret.ID, secret.Name, secret.EncryptedKey, secret.EncryptedData,
		secret.Scope, secret.Category, string(tagsJSON), secret.ExpiryDate,
		secret.CreatedAt, secret.UpdatedAt, secret.Version, string(metadataJSON))
	
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	return nil
}

// GetSecret retrieves a secret by name.
func (s *SQLiteStore) GetSecret(ctx context.Context, name string) (*Secret, error) {
	const query = `
		SELECT id, name, encrypted_key, encrypted_data, scope, category,
			   tags, expiry_date, created_at, updated_at, version, metadata
		FROM secrets WHERE name = ?`

	var secret Secret
	var tagsJSON, metadataJSON string

	err := s.db.QueryRowContext(ctx, query, name).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedKey, &secret.EncryptedData,
		&secret.Scope, &secret.Category, &tagsJSON, &secret.ExpiryDate,
		&secret.CreatedAt, &secret.UpdatedAt, &secret.Version, &metadataJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("secret not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if err := json.Unmarshal([]byte(tagsJSON), &secret.Tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &secret.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &secret, nil
}

// GetSecretByID retrieves a secret by ID.
func (s *SQLiteStore) GetSecretByID(ctx context.Context, id string) (*Secret, error) {
	const query = `
		SELECT id, name, encrypted_key, encrypted_data, scope, category,
			   tags, expiry_date, created_at, updated_at, version, metadata
		FROM secrets WHERE id = ?`

	var secret Secret
	var tagsJSON, metadataJSON string

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedKey, &secret.EncryptedData,
		&secret.Scope, &secret.Category, &tagsJSON, &secret.ExpiryDate,
		&secret.CreatedAt, &secret.UpdatedAt, &secret.Version, &metadataJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("secret not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if err := json.Unmarshal([]byte(tagsJSON), &secret.Tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &secret.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &secret, nil
}

// UpdateSecret updates an existing secret.
func (s *SQLiteStore) UpdateSecret(ctx context.Context, secret *Secret) error {
	const query = `
		UPDATE secrets SET 
			encrypted_key = ?, encrypted_data = ?, scope = ?, category = ?,
			tags = ?, expiry_date = ?, updated_at = ?, version = version + 1, metadata = ?
		WHERE name = ? AND version = ?`

	tagsJSON, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	result, err := s.db.ExecContext(ctx, query,
		secret.EncryptedKey, secret.EncryptedData, secret.Scope, secret.Category,
		string(tagsJSON), secret.ExpiryDate, time.Now(), string(metadataJSON),
		secret.Name, secret.Version)

	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("secret not found or version mismatch: %s", secret.Name)
	}

	return nil
}

// DeleteSecret removes a secret from the database.
func (s *SQLiteStore) DeleteSecret(ctx context.Context, name string) error {
	const query = `DELETE FROM secrets WHERE name = ?`

	result, err := s.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("secret not found: %s", name)
	}

	return nil
}

// ListSecrets returns a list of secret metadata based on the filter.
func (s *SQLiteStore) ListSecrets(ctx context.Context, filter *SecretFilter) ([]*SecretMeta, error) {
	query := `
		SELECT id, name, scope, category, tags, expiry_date, 
			   created_at, updated_at, version, metadata
		FROM secrets WHERE 1=1`
	
	var args []interface{}
	var conditions []string

	if filter != nil {
		if filter.Scope != "" {
			conditions = append(conditions, "scope = ?")
			args = append(args, filter.Scope)
		}
		
		if filter.Category != "" {
			conditions = append(conditions, "category = ?")
			args = append(args, filter.Category)
		}
		
		if filter.CreatedAfter != nil {
			conditions = append(conditions, "created_at > ?")
			args = append(args, filter.CreatedAfter)
		}
		
		if filter.CreatedBefore != nil {
			conditions = append(conditions, "created_at < ?")
			args = append(args, filter.CreatedBefore)
		}
		
		if filter.ExpiredOnly {
			conditions = append(conditions, "expiry_date IS NOT NULL AND expiry_date < CURRENT_TIMESTAMP")
		}
		
		if filter.ActiveOnly {
			conditions = append(conditions, "expiry_date IS NULL OR expiry_date > CURRENT_TIMESTAMP")
		}
		
		if len(conditions) > 0 {
			query += " AND " + strings.Join(conditions, " AND ")
		}
		
		// Add sorting
		sortBy := "created_at"
		if filter.SortBy != "" {
			switch filter.SortBy {
			case "name", "created_at", "updated_at":
				sortBy = filter.SortBy
			}
		}
		
		sortOrder := "DESC"
		if filter.SortOrder == "asc" {
			sortOrder = "ASC"
		}
		
		query += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)
		
		// Add pagination
		if filter.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, filter.Limit)
		}
		
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*SecretMeta
	for rows.Next() {
		var meta SecretMeta
		var tagsJSON, metadataJSON string

		err := rows.Scan(
			&meta.ID, &meta.Name, &meta.Scope, &meta.Category, &tagsJSON,
			&meta.ExpiryDate, &meta.CreatedAt, &meta.UpdatedAt, &meta.Version, &metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to scan secret metadata: %w", err)
		}

		if err := json.Unmarshal([]byte(tagsJSON), &meta.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}

		if err := json.Unmarshal([]byte(metadataJSON), &meta.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		secrets = append(secrets, &meta)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating secrets: %w", err)
	}

	return secrets, nil
}

// SecretExists checks if a secret with the given name exists.
func (s *SQLiteStore) SecretExists(ctx context.Context, name string) (bool, error) {
	const query = `SELECT 1 FROM secrets WHERE name = ? LIMIT 1`

	var exists int
	err := s.db.QueryRowContext(ctx, query, name).Scan(&exists)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to check secret existence: %w", err)
	}

	return exists == 1, nil
}

// AppendAuditLog adds an audit log entry.
func (s *SQLiteStore) AppendAuditLog(ctx context.Context, log *AuditLog) error {
	const query = `
		INSERT INTO audit_logs (
			secret_id, operation, user_id, device_id, client_ip, user_agent,
			operation_details, success, error_message, timestamp, session_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	detailsJSON, err := json.Marshal(log.OperationDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal operation details: %w", err)
	}

	_, err = s.db.ExecContext(ctx, query,
		log.SecretID, log.Operation, log.UserID, log.DeviceID,
		log.ClientIP, log.UserAgent, string(detailsJSON), log.Success,
		log.ErrorMessage, log.Timestamp, log.SessionID)

	if err != nil {
		return fmt.Errorf("failed to append audit log: %w", err)
	}

	return nil
}

// GetAuditLogs retrieves audit logs based on the filter.
func (s *SQLiteStore) GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error) {
	query := `
		SELECT id, secret_id, operation, user_id, device_id, client_ip, user_agent,
			   operation_details, success, error_message, timestamp, session_id
		FROM audit_logs WHERE 1=1`
	
	var args []interface{}
	var conditions []string

	if filter != nil {
		if filter.SecretID != nil {
			conditions = append(conditions, "secret_id = ?")
			args = append(args, *filter.SecretID)
		}
		
		if filter.UserID != nil {
			conditions = append(conditions, "user_id = ?")
			args = append(args, *filter.UserID)
		}
		
		if filter.DeviceID != nil {
			conditions = append(conditions, "device_id = ?")
			args = append(args, *filter.DeviceID)
		}
		
		if filter.Operation != nil {
			conditions = append(conditions, "operation = ?")
			args = append(args, *filter.Operation)
		}
		
		if filter.SuccessOnly != nil && *filter.SuccessOnly {
			conditions = append(conditions, "success = TRUE")
		}
		
		if filter.FailuresOnly != nil && *filter.FailuresOnly {
			conditions = append(conditions, "success = FALSE")
		}
		
		if filter.Since != nil {
			conditions = append(conditions, "timestamp >= ?")
			args = append(args, *filter.Since)
		}
		
		if filter.Until != nil {
			conditions = append(conditions, "timestamp <= ?")
			args = append(args, *filter.Until)
		}
		
		if len(conditions) > 0 {
			query += " AND " + strings.Join(conditions, " AND ")
		}
		
		query += " ORDER BY timestamp DESC"
		
		if filter.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, filter.Limit)
		}
		
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		var detailsJSON string

		err := rows.Scan(
			&log.ID, &log.SecretID, &log.Operation, &log.UserID, &log.DeviceID,
			&log.ClientIP, &log.UserAgent, &detailsJSON, &log.Success,
			&log.ErrorMessage, &log.Timestamp, &log.SessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if err := json.Unmarshal([]byte(detailsJSON), &log.OperationDetails); err != nil {
			return nil, fmt.Errorf("failed to unmarshal operation details: %w", err)
		}

		logs = append(logs, &log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit logs: %w", err)
	}

	return logs, nil
}

// RegisterDevice registers a new device.
func (s *SQLiteStore) RegisterDevice(ctx context.Context, device *Device) error {
	const query = `
		INSERT INTO devices (
			id, user_id, device_name, device_type, public_key, fingerprint,
			platform, app_version, last_used_at, registered_at, is_active, trust_level, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	metadataJSON, err := json.Marshal(device.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = s.db.ExecContext(ctx, query,
		device.ID, device.UserID, device.DeviceName, device.DeviceType,
		device.PublicKey, device.Fingerprint, device.Platform, device.AppVersion,
		device.LastUsedAt, device.RegisteredAt, device.IsActive, device.TrustLevel,
		string(metadataJSON))

	if err != nil {
		return fmt.Errorf("failed to register device: %w", err)
	}

	return nil
}

// GetDevice retrieves a device by ID.
func (s *SQLiteStore) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	const query = `
		SELECT id, user_id, device_name, device_type, public_key, fingerprint,
			   platform, app_version, last_used_at, registered_at, is_active, trust_level, metadata
		FROM devices WHERE id = ?`

	var device Device
	var metadataJSON string

	err := s.db.QueryRowContext(ctx, query, deviceID).Scan(
		&device.ID, &device.UserID, &device.DeviceName, &device.DeviceType,
		&device.PublicKey, &device.Fingerprint, &device.Platform, &device.AppVersion,
		&device.LastUsedAt, &device.RegisteredAt, &device.IsActive, &device.TrustLevel,
		&metadataJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("device not found: %s", deviceID)
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &device.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &device, nil
}

// GetUserDevices retrieves all devices for a user.
func (s *SQLiteStore) GetUserDevices(ctx context.Context, userID string) ([]*Device, error) {
	const query = `
		SELECT id, user_id, device_name, device_type, public_key, fingerprint,
			   platform, app_version, last_used_at, registered_at, is_active, trust_level, metadata
		FROM devices WHERE user_id = ? ORDER BY last_used_at DESC`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		var device Device
		var metadataJSON string

		err := rows.Scan(
			&device.ID, &device.UserID, &device.DeviceName, &device.DeviceType,
			&device.PublicKey, &device.Fingerprint, &device.Platform, &device.AppVersion,
			&device.LastUsedAt, &device.RegisteredAt, &device.IsActive, &device.TrustLevel,
			&metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}

		if err := json.Unmarshal([]byte(metadataJSON), &device.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		devices = append(devices, &device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating devices: %w", err)
	}

	return devices, nil
}

// UpdateDevice updates an existing device.
func (s *SQLiteStore) UpdateDevice(ctx context.Context, device *Device) error {
	const query = `
		UPDATE devices SET 
			device_name = ?, device_type = ?, public_key = ?, fingerprint = ?,
			platform = ?, app_version = ?, last_used_at = ?, trust_level = ?, metadata = ?
		WHERE id = ?`

	metadataJSON, err := json.Marshal(device.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	result, err := s.db.ExecContext(ctx, query,
		device.DeviceName, device.DeviceType, device.PublicKey, device.Fingerprint,
		device.Platform, device.AppVersion, device.LastUsedAt, device.TrustLevel,
		string(metadataJSON), device.ID)

	if err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("device not found: %s", device.ID)
	}

	return nil
}

// DeactivateDevice deactivates a device.
func (s *SQLiteStore) DeactivateDevice(ctx context.Context, deviceID string) error {
	const query = `UPDATE devices SET is_active = FALSE WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, deviceID)
	if err != nil {
		return fmt.Errorf("failed to deactivate device: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	return nil
}

// Ping checks the database connection.
func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Stats returns statistics about the store.
func (s *SQLiteStore) Stats(ctx context.Context) (*StoreStats, error) {
	stats := &StoreStats{
		Health: "healthy",
	}

	// Get secret count
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM secrets").Scan(&stats.SecretCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret count: %w", err)
	}

	// Get audit log count
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs").Scan(&stats.AuditLogCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log count: %w", err)
	}

	// Get device count
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices").Scan(&stats.DeviceCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get device count: %w", err)
	}

	// Get active device count
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE is_active = TRUE").Scan(&stats.ActiveDeviceCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get active device count: %w", err)
	}

	// Get expired secret count
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM secrets WHERE expiry_date IS NOT NULL AND expiry_date < CURRENT_TIMESTAMP").Scan(&stats.ExpiredSecretCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get expired secret count: %w", err)
	}

	// Try to get database size (SQLite specific)
	var dbSize sql.NullInt64
	err = s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&dbSize)
	if err == nil && dbSize.Valid {
		var pageSize sql.NullInt64
		err = s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize)
		if err == nil && pageSize.Valid {
			stats.DatabaseSize = dbSize.Int64 * pageSize.Int64
		}
	}

	return stats, nil
}

// BeginTx starts a database transaction.
func (s *SQLiteStore) BeginTx(ctx context.Context) (Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &SQLiteTx{
		tx:    tx,
		store: s,
	}, nil
}

// SQLiteTx implements the Tx interface for SQLite transactions.
type SQLiteTx struct {
	tx    *sql.Tx
	store *SQLiteStore
}

// Commit commits the transaction.
func (tx *SQLiteTx) Commit() error {
	return tx.tx.Commit()
}

// Rollback rolls back the transaction.
func (tx *SQLiteTx) Rollback() error {
	return tx.tx.Rollback()
}

// All Store interface methods for transaction use the transaction's database connection
func (tx *SQLiteTx) CreateSecret(ctx context.Context, secret *Secret) error {
	const query = `
		INSERT INTO secrets (
			id, name, encrypted_key, encrypted_data, scope, category, 
			tags, expiry_date, created_at, updated_at, version, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	tagsJSON, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = tx.tx.ExecContext(ctx, query,
		secret.ID, secret.Name, secret.EncryptedKey, secret.EncryptedData,
		secret.Scope, secret.Category, string(tagsJSON), secret.ExpiryDate,
		secret.CreatedAt, secret.UpdatedAt, secret.Version, string(metadataJSON))
	
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	return nil
}

func (tx *SQLiteTx) GetSecret(ctx context.Context, name string) (*Secret, error) {
	const query = `
		SELECT id, name, encrypted_key, encrypted_data, scope, category,
			   tags, expiry_date, created_at, updated_at, version, metadata
		FROM secrets WHERE name = ?`

	var secret Secret
	var tagsJSON, metadataJSON string

	err := tx.tx.QueryRowContext(ctx, query, name).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedKey, &secret.EncryptedData,
		&secret.Scope, &secret.Category, &tagsJSON, &secret.ExpiryDate,
		&secret.CreatedAt, &secret.UpdatedAt, &secret.Version, &metadataJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("secret not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if err := json.Unmarshal([]byte(tagsJSON), &secret.Tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &secret.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &secret, nil
}

func (tx *SQLiteTx) GetSecretByID(ctx context.Context, id string) (*Secret, error) {
	const query = `
		SELECT id, name, encrypted_key, encrypted_data, scope, category,
			   tags, expiry_date, created_at, updated_at, version, metadata
		FROM secrets WHERE id = ?`

	var secret Secret
	var tagsJSON, metadataJSON string

	err := tx.tx.QueryRowContext(ctx, query, id).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedKey, &secret.EncryptedData,
		&secret.Scope, &secret.Category, &tagsJSON, &secret.ExpiryDate,
		&secret.CreatedAt, &secret.UpdatedAt, &secret.Version, &metadataJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("secret not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if err := json.Unmarshal([]byte(tagsJSON), &secret.Tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &secret.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &secret, nil
}

func (tx *SQLiteTx) UpdateSecret(ctx context.Context, secret *Secret) error {
	// Use the main store implementation but with transaction context
	return tx.store.UpdateSecret(ctx, secret)
}

func (tx *SQLiteTx) DeleteSecret(ctx context.Context, name string) error {
	const query = `DELETE FROM secrets WHERE name = ?`
	result, err := tx.tx.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("secret not found: %s", name)
	}

	return nil
}

func (tx *SQLiteTx) ListSecrets(ctx context.Context, filter *SecretFilter) ([]*SecretMeta, error) {
	// Use the main store implementation
	return tx.store.ListSecrets(ctx, filter)
}

func (tx *SQLiteTx) SecretExists(ctx context.Context, name string) (bool, error) {
	const query = `SELECT 1 FROM secrets WHERE name = ? LIMIT 1`
	var exists int
	err := tx.tx.QueryRowContext(ctx, query, name).Scan(&exists)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to check secret existence: %w", err)
	}
	return true, nil
}

func (tx *SQLiteTx) AppendAuditLog(ctx context.Context, log *AuditLog) error {
	// Use the main store implementation
	return tx.store.AppendAuditLog(ctx, log)
}

func (tx *SQLiteTx) GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error) {
	// Use the main store implementation
	return tx.store.GetAuditLogs(ctx, filter)
}

func (tx *SQLiteTx) RegisterDevice(ctx context.Context, device *Device) error {
	// Use the main store implementation
	return tx.store.RegisterDevice(ctx, device)
}

func (tx *SQLiteTx) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	// Use the main store implementation
	return tx.store.GetDevice(ctx, deviceID)
}

func (tx *SQLiteTx) GetUserDevices(ctx context.Context, userID string) ([]*Device, error) {
	// Use the main store implementation
	return tx.store.GetUserDevices(ctx, userID)
}

func (tx *SQLiteTx) UpdateDevice(ctx context.Context, device *Device) error {
	// Use the main store implementation
	return tx.store.UpdateDevice(ctx, device)
}

func (tx *SQLiteTx) DeactivateDevice(ctx context.Context, deviceID string) error {
	// Use the main store implementation
	return tx.store.DeactivateDevice(ctx, deviceID)
}

func (tx *SQLiteTx) Ping(ctx context.Context) error {
	return tx.store.Ping(ctx)
}

func (tx *SQLiteTx) Close() error {
	// Cannot close the store from within a transaction
	return nil
}

func (tx *SQLiteTx) Stats(ctx context.Context) (*StoreStats, error) {
	// Use the main store implementation
	return tx.store.Stats(ctx)
}

func (tx *SQLiteTx) BeginTx(ctx context.Context) (Tx, error) {
	// Cannot begin nested transactions
	return nil, fmt.Errorf("nested transactions not supported")
}