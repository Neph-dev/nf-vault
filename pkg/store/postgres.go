// Package store provides PostgreSQL implementation of the Store interface.
// This implementation uses PostgreSQL as the backend database with connection pooling and transaction support.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

// PostgreSQLStore implements the Store interface using PostgreSQL as the backend.
type PostgreSQLStore struct {
	pool         *pgxpool.Pool
	db           *sql.DB
	migrationDir string
}

// NewPostgreSQLStore creates a new PostgreSQL store instance.
func NewPostgreSQLStore(databaseURL, migrationDir string) (*PostgreSQLStore, error) {
	// Create connection pool
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create sql.DB from pool for migrations
	db := stdlib.OpenDBFromPool(pool)

	store := &PostgreSQLStore{
		pool:         pool,
		db:           db,
		migrationDir: migrationDir,
	}

	// Run migrations
	if err := store.runMigrations(); err != nil {
		store.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return store, nil
}

// Close closes the database connection pool.
func (s *PostgreSQLStore) Close() error {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Ping checks if the database connection is alive.
func (s *PostgreSQLStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// runMigrations applies database migrations.
func (s *PostgreSQLStore) runMigrations() error {
	if s.migrationDir == "" {
		return nil // Skip migrations if no directory specified
	}

	driver, err := postgres.WithInstance(s.db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	source, err := (&file.File{}).Open("file://" + s.migrationDir)
	if err != nil {
		return fmt.Errorf("failed to open migration source: %w", err)
	}

	m, err := migrate.NewWithInstance("file", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// CreateSecret stores a new secret in the database.
func (s *PostgreSQLStore) CreateSecret(ctx context.Context, secret *Secret) error {
	const query = `
		INSERT INTO secrets (
			id, name, encrypted_key, encrypted_data, scope, category, 
			tags, expiry_date, created_at, updated_at, version, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	tagsJSON, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx, query,
		secret.ID, secret.Name, secret.EncryptedKey, secret.EncryptedData,
		secret.Scope, secret.Category, string(tagsJSON), secret.ExpiryDate,
		secret.CreatedAt, secret.UpdatedAt, secret.Version, string(metadataJSON))
	
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	return nil
}

// GetSecret retrieves a secret by name.
func (s *PostgreSQLStore) GetSecret(ctx context.Context, name string) (*Secret, error) {
	const query = `
		SELECT id, name, encrypted_key, encrypted_data, scope, category,
			   tags, expiry_date, created_at, updated_at, version, metadata
		FROM secrets WHERE name = $1`

	var secret Secret
	var tagsJSON, metadataJSON string

	err := s.pool.QueryRow(ctx, query, name).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedKey, &secret.EncryptedData,
		&secret.Scope, &secret.Category, &tagsJSON, &secret.ExpiryDate,
		&secret.CreatedAt, &secret.UpdatedAt, &secret.Version, &metadataJSON)

	if err != nil {
		if err.Error() == "no rows in result set" {
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
func (s *PostgreSQLStore) GetSecretByID(ctx context.Context, id string) (*Secret, error) {
	const query = `
		SELECT id, name, encrypted_key, encrypted_data, scope, category,
			   tags, expiry_date, created_at, updated_at, version, metadata
		FROM secrets WHERE id = $1`

	var secret Secret
	var tagsJSON, metadataJSON string

	err := s.pool.QueryRow(ctx, query, id).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedKey, &secret.EncryptedData,
		&secret.Scope, &secret.Category, &tagsJSON, &secret.ExpiryDate,
		&secret.CreatedAt, &secret.UpdatedAt, &secret.Version, &metadataJSON)

	if err != nil {
		if err.Error() == "no rows in result set" {
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
func (s *PostgreSQLStore) UpdateSecret(ctx context.Context, secret *Secret) error {
	const query = `
		UPDATE secrets 
		SET encrypted_key = $3, encrypted_data = $4, scope = $5, category = $6,
			tags = $7, expiry_date = $8, updated_at = $9, version = $10, metadata = $11
		WHERE name = $1 AND version = $2`

	tagsJSON, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	result, err := s.pool.Exec(ctx, query,
		secret.Name, secret.Version, secret.EncryptedKey, secret.EncryptedData,
		secret.Scope, secret.Category, string(tagsJSON), secret.ExpiryDate,
		time.Now(), secret.Version+1, string(metadataJSON))

	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("secret not found or version mismatch: %s", secret.Name)
	}

	secret.Version++
	secret.UpdatedAt = time.Now()

	return nil
}

// DeleteSecret removes a secret from the database.
func (s *PostgreSQLStore) DeleteSecret(ctx context.Context, name string) error {
	const query = `DELETE FROM secrets WHERE name = $1`
	result, err := s.pool.Exec(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("secret not found: %s", name)
	}

	return nil
}

// SecretExists checks if a secret with the given name exists.
func (s *PostgreSQLStore) SecretExists(ctx context.Context, name string) (bool, error) {
	const query = `SELECT 1 FROM secrets WHERE name = $1 LIMIT 1`
	var exists int
	err := s.pool.QueryRow(ctx, query, name).Scan(&exists)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, nil
		}
		return false, fmt.Errorf("failed to check secret existence: %w", err)
	}
	return true, nil
}

// ListSecrets returns a list of secret metadata based on the provided filter.
func (s *PostgreSQLStore) ListSecrets(ctx context.Context, filter *SecretFilter) ([]*SecretMeta, error) {
	query := `
		SELECT id, name, scope, category, tags, expiry_date, created_at, updated_at, version
		FROM secrets`

	var args []interface{}
	var conditions []string
	argIndex := 1

	// Apply filters
	if filter != nil {
		if filter.Scope != "" {
			conditions = append(conditions, fmt.Sprintf("scope = $%d", argIndex))
			args = append(args, filter.Scope)
			argIndex++
		}

		if filter.Category != "" {
			conditions = append(conditions, fmt.Sprintf("category = $%d", argIndex))
			args = append(args, filter.Category)
			argIndex++
		}

		if filter.ActiveOnly {
			conditions = append(conditions, "(expiry_date IS NULL OR expiry_date > NOW())")
		}

		if filter.ExpiredOnly {
			conditions = append(conditions, "expiry_date IS NOT NULL AND expiry_date <= NOW()")
		}

		if filter.CreatedAfter != nil {
			conditions = append(conditions, fmt.Sprintf("created_at > $%d", argIndex))
			args = append(args, *filter.CreatedAfter)
			argIndex++
		}

		if filter.CreatedBefore != nil {
			conditions = append(conditions, fmt.Sprintf("created_at < $%d", argIndex))
			args = append(args, *filter.CreatedBefore)
			argIndex++
		}
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	// Apply sorting
	if filter != nil && filter.SortBy != "" {
		sortOrder := "ASC"
		if filter.SortOrder == "desc" {
			sortOrder = "DESC"
		}
		query += fmt.Sprintf(" ORDER BY %s %s", filter.SortBy, sortOrder)
	} else {
		query += " ORDER BY created_at DESC"
	}

	// Apply pagination
	if filter != nil && filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++

		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*SecretMeta
	for rows.Next() {
		var secret SecretMeta
		var tagsJSON string

		err := rows.Scan(
			&secret.ID, &secret.Name, &secret.Scope, &secret.Category,
			&tagsJSON, &secret.ExpiryDate, &secret.CreatedAt,
			&secret.UpdatedAt, &secret.Version)

		if err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}

		if err := json.Unmarshal([]byte(tagsJSON), &secret.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}

		secrets = append(secrets, &secret)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return secrets, nil
}

// AppendAuditLog adds a new audit log entry.
func (s *PostgreSQLStore) AppendAuditLog(ctx context.Context, log *AuditLog) error {
	const query = `
		INSERT INTO audit_logs (
			secret_id, operation, user_id, device_id, client_ip, user_agent,
			operation_details, success, error_message, timestamp, session_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	operationDetailsJSON, err := json.Marshal(log.OperationDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal operation details: %w", err)
	}

	_, err = s.pool.Exec(ctx, query,
		log.SecretID, log.Operation, log.UserID, log.DeviceID,
		log.ClientIP, log.UserAgent, string(operationDetailsJSON),
		log.Success, log.ErrorMessage, log.Timestamp, log.SessionID)

	if err != nil {
		return fmt.Errorf("failed to append audit log: %w", err)
	}

	return nil
}

// GetAuditLogs retrieves audit logs based on the provided filter.
func (s *PostgreSQLStore) GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error) {
	query := `
		SELECT id, secret_id, operation, user_id, device_id, client_ip, user_agent,
			   operation_details, success, error_message, timestamp, session_id
		FROM audit_logs`

	var args []interface{}
	var conditions []string
	argIndex := 1

	// Apply filters
	if filter != nil {
		if filter.SecretID != nil {
			conditions = append(conditions, fmt.Sprintf("secret_id = $%d", argIndex))
			args = append(args, *filter.SecretID)
			argIndex++
		}

		if filter.UserID != nil {
			conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIndex))
			args = append(args, *filter.UserID)
			argIndex++
		}

		if filter.Operation != nil {
			conditions = append(conditions, fmt.Sprintf("operation = $%d", argIndex))
			args = append(args, *filter.Operation)
			argIndex++
		}

		if filter.DeviceID != nil {
			conditions = append(conditions, fmt.Sprintf("device_id = $%d", argIndex))
			args = append(args, *filter.DeviceID)
			argIndex++
		}

		if filter.SuccessOnly != nil && *filter.SuccessOnly {
			conditions = append(conditions, "success = true")
		}

		if filter.FailuresOnly != nil && *filter.FailuresOnly {
			conditions = append(conditions, "success = false")
		}

		if filter.Since != nil {
			conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIndex))
			args = append(args, *filter.Since)
			argIndex++
		}

		if filter.Until != nil {
			conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIndex))
			args = append(args, *filter.Until)
			argIndex++
		}
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY timestamp DESC"

	// Apply pagination
	if filter != nil && filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++

		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		var operationDetailsJSON string

		err := rows.Scan(
			&log.ID, &log.SecretID, &log.Operation, &log.UserID,
			&log.DeviceID, &log.ClientIP, &log.UserAgent,
			&operationDetailsJSON, &log.Success, &log.ErrorMessage,
			&log.Timestamp, &log.SessionID)

		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if err := json.Unmarshal([]byte(operationDetailsJSON), &log.OperationDetails); err != nil {
			return nil, fmt.Errorf("failed to unmarshal operation details: %w", err)
		}

		logs = append(logs, &log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return logs, nil
}

// RegisterDevice registers a new device.
func (s *PostgreSQLStore) RegisterDevice(ctx context.Context, device *Device) error {
	const query = `
		INSERT INTO devices (
			id, user_id, device_name, device_type, public_key, fingerprint,
			platform, app_version, last_used_at, registered_at, is_active,
			trust_level, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	metadataJSON, err := json.Marshal(device.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx, query,
		device.ID, device.UserID, device.DeviceName, device.DeviceType,
		device.PublicKey, device.Fingerprint, device.Platform,
		device.AppVersion, device.LastUsedAt, device.RegisteredAt,
		device.IsActive, device.TrustLevel, string(metadataJSON))

	if err != nil {
		return fmt.Errorf("failed to register device: %w", err)
	}

	return nil
}

// GetDevice retrieves a device by ID.
func (s *PostgreSQLStore) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	const query = `
		SELECT id, user_id, device_name, device_type, public_key, fingerprint,
			   platform, app_version, last_used_at, registered_at, is_active,
			   trust_level, metadata
		FROM devices WHERE id = $1`

	var device Device
	var metadataJSON string

	err := s.pool.QueryRow(ctx, query, deviceID).Scan(
		&device.ID, &device.UserID, &device.DeviceName, &device.DeviceType,
		&device.PublicKey, &device.Fingerprint, &device.Platform,
		&device.AppVersion, &device.LastUsedAt, &device.RegisteredAt,
		&device.IsActive, &device.TrustLevel, &metadataJSON)

	if err != nil {
		if err.Error() == "no rows in result set" {
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
func (s *PostgreSQLStore) GetUserDevices(ctx context.Context, userID string) ([]*Device, error) {
	const query = `
		SELECT id, user_id, device_name, device_type, public_key, fingerprint,
			   platform, app_version, last_used_at, registered_at, is_active,
			   trust_level, metadata
		FROM devices WHERE user_id = $1 ORDER BY registered_at DESC`

	rows, err := s.pool.Query(ctx, query, userID)
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
			&device.PublicKey, &device.Fingerprint, &device.Platform,
			&device.AppVersion, &device.LastUsedAt, &device.RegisteredAt,
			&device.IsActive, &device.TrustLevel, &metadataJSON)

		if err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}

		if err := json.Unmarshal([]byte(metadataJSON), &device.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		devices = append(devices, &device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return devices, nil
}

// UpdateDevice updates an existing device.
func (s *PostgreSQLStore) UpdateDevice(ctx context.Context, device *Device) error {
	const query = `
		UPDATE devices 
		SET device_name = $2, device_type = $3, public_key = $4, fingerprint = $5,
			platform = $6, app_version = $7, last_used_at = $8, is_active = $9,
			trust_level = $10, metadata = $11
		WHERE id = $1`

	metadataJSON, err := json.Marshal(device.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	result, err := s.pool.Exec(ctx, query,
		device.ID, device.DeviceName, device.DeviceType, device.PublicKey,
		device.Fingerprint, device.Platform, device.AppVersion,
		device.LastUsedAt, device.IsActive, device.TrustLevel, string(metadataJSON))

	if err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("device not found: %s", device.ID)
	}

	return nil
}

// DeactivateDevice deactivates a device.
func (s *PostgreSQLStore) DeactivateDevice(ctx context.Context, deviceID string) error {
	const query = `UPDATE devices SET is_active = false WHERE id = $1`
	result, err := s.pool.Exec(ctx, query, deviceID)
	if err != nil {
		return fmt.Errorf("failed to deactivate device: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	return nil
}

// Stats returns store statistics.
func (s *PostgreSQLStore) Stats(ctx context.Context) (*StoreStats, error) {
	stats := &StoreStats{
		Health: "healthy",
	}

	// Get secret count
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM secrets").Scan(&stats.SecretCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret count: %w", err)
	}

	// Get audit log count
	err = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_logs").Scan(&stats.AuditLogCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log count: %w", err)
	}

	// Get device count
	err = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM devices").Scan(&stats.DeviceCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get device count: %w", err)
	}

	// Get active device count
	err = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM devices WHERE is_active = true").Scan(&stats.ActiveDeviceCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get active device count: %w", err)
	}

	return stats, nil
}

// BeginTx starts a database transaction.
func (s *PostgreSQLStore) BeginTx(ctx context.Context) (Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &PostgreSQLTx{
		tx:    tx,
		store: s,
	}, nil
}

// PostgreSQLTx implements the Tx interface for PostgreSQL transactions.
type PostgreSQLTx struct {
	tx    pgx.Tx
	store *PostgreSQLStore
}

// Commit commits the transaction.
func (tx *PostgreSQLTx) Commit() error {
	return tx.tx.Commit(context.Background())
}

// Rollback rolls back the transaction.
func (tx *PostgreSQLTx) Rollback() error {
	return tx.tx.Rollback(context.Background())
}

// All Store interface methods for transaction use the transaction's database connection
func (tx *PostgreSQLTx) CreateSecret(ctx context.Context, secret *Secret) error {
	const query = `
		INSERT INTO secrets (
			id, name, encrypted_key, encrypted_data, scope, category, 
			tags, expiry_date, created_at, updated_at, version, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	tagsJSON, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = tx.tx.Exec(ctx, query,
		secret.ID, secret.Name, secret.EncryptedKey, secret.EncryptedData,
		secret.Scope, secret.Category, string(tagsJSON), secret.ExpiryDate,
		secret.CreatedAt, secret.UpdatedAt, secret.Version, string(metadataJSON))
	
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	return nil
}

func (tx *PostgreSQLTx) GetSecret(ctx context.Context, name string) (*Secret, error) {
	const query = `
		SELECT id, name, encrypted_key, encrypted_data, scope, category,
			   tags, expiry_date, created_at, updated_at, version, metadata
		FROM secrets WHERE name = $1`

	var secret Secret
	var tagsJSON, metadataJSON string

	err := tx.tx.QueryRow(ctx, query, name).Scan(
		&secret.ID, &secret.Name, &secret.EncryptedKey, &secret.EncryptedData,
		&secret.Scope, &secret.Category, &tagsJSON, &secret.ExpiryDate,
		&secret.CreatedAt, &secret.UpdatedAt, &secret.Version, &metadataJSON)

	if err != nil {
		if err.Error() == "no rows in result set" {
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

// Simplified transaction methods that delegate to the main store
func (tx *PostgreSQLTx) GetSecretByID(ctx context.Context, id string) (*Secret, error) {
	return tx.store.GetSecretByID(ctx, id)
}

func (tx *PostgreSQLTx) UpdateSecret(ctx context.Context, secret *Secret) error {
	return tx.store.UpdateSecret(ctx, secret)
}

func (tx *PostgreSQLTx) DeleteSecret(ctx context.Context, name string) error {
	const query = `DELETE FROM secrets WHERE name = $1`
	result, err := tx.tx.Exec(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("secret not found: %s", name)
	}

	return nil
}

func (tx *PostgreSQLTx) SecretExists(ctx context.Context, name string) (bool, error) {
	const query = `SELECT 1 FROM secrets WHERE name = $1 LIMIT 1`
	var exists int
	err := tx.tx.QueryRow(ctx, query, name).Scan(&exists)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, nil
		}
		return false, fmt.Errorf("failed to check secret existence: %w", err)
	}
	return true, nil
}

func (tx *PostgreSQLTx) ListSecrets(ctx context.Context, filter *SecretFilter) ([]*SecretMeta, error) {
	return tx.store.ListSecrets(ctx, filter)
}

func (tx *PostgreSQLTx) AppendAuditLog(ctx context.Context, log *AuditLog) error {
	return tx.store.AppendAuditLog(ctx, log)
}

func (tx *PostgreSQLTx) GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error) {
	return tx.store.GetAuditLogs(ctx, filter)
}

func (tx *PostgreSQLTx) RegisterDevice(ctx context.Context, device *Device) error {
	return tx.store.RegisterDevice(ctx, device)
}

func (tx *PostgreSQLTx) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	return tx.store.GetDevice(ctx, deviceID)
}

func (tx *PostgreSQLTx) GetUserDevices(ctx context.Context, userID string) ([]*Device, error) {
	return tx.store.GetUserDevices(ctx, userID)
}

func (tx *PostgreSQLTx) UpdateDevice(ctx context.Context, device *Device) error {
	return tx.store.UpdateDevice(ctx, device)
}

func (tx *PostgreSQLTx) DeactivateDevice(ctx context.Context, deviceID string) error {
	return tx.store.DeactivateDevice(ctx, deviceID)
}

func (tx *PostgreSQLTx) Ping(ctx context.Context) error {
	return tx.store.Ping(ctx)
}

func (tx *PostgreSQLTx) Close() error {
	// Cannot close the store from within a transaction
	return nil
}

func (tx *PostgreSQLTx) Stats(ctx context.Context) (*StoreStats, error) {
	return tx.store.Stats(ctx)
}

func (tx *PostgreSQLTx) BeginTx(ctx context.Context) (Tx, error) {
	// Cannot begin nested transactions
	return nil, fmt.Errorf("nested transactions not supported")
}