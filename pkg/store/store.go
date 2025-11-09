// Package store provides persistent storage interfaces and implementations for the vault.
// It supports multiple backends including SQLite and PostgreSQL with a unified interface.
package store

import (
	"context"
	"time"
)

// Store defines the interface for persistent storage operations.
// All implementations must be thread-safe and support transactions.
type Store interface {
	// Secret operations
	CreateSecret(ctx context.Context, secret *Secret) error
	GetSecret(ctx context.Context, name string) (*Secret, error)
	GetSecretByID(ctx context.Context, id string) (*Secret, error)
	UpdateSecret(ctx context.Context, secret *Secret) error
	DeleteSecret(ctx context.Context, name string) error
	ListSecrets(ctx context.Context, filter *SecretFilter) ([]*SecretMeta, error)
	SecretExists(ctx context.Context, name string) (bool, error)
	
	// Audit log operations
	AppendAuditLog(ctx context.Context, log *AuditLog) error
	GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error)
	
	// Device operations
	RegisterDevice(ctx context.Context, device *Device) error
	GetDevice(ctx context.Context, deviceID string) (*Device, error)
	GetUserDevices(ctx context.Context, userID string) ([]*Device, error)
	UpdateDevice(ctx context.Context, device *Device) error
	DeactivateDevice(ctx context.Context, deviceID string) error
	
	// Health and maintenance
	Ping(ctx context.Context) error
	Close() error
	Stats(ctx context.Context) (*StoreStats, error)
	
	// Transaction support
	BeginTx(ctx context.Context) (Tx, error)
}

// Tx represents a database transaction with the same Store interface.
type Tx interface {
	Store
	Commit() error
	Rollback() error
}

// Secret represents an encrypted secret with metadata.
type Secret struct {
	ID           string            `json:"id" db:"id"`
	Name         string            `json:"name" db:"name"`
	EncryptedKey []byte            `json:"encrypted_key" db:"encrypted_key"`
	EncryptedData []byte           `json:"encrypted_data" db:"encrypted_data"`
	Scope        string            `json:"scope" db:"scope"`
	Category     string            `json:"category" db:"category"`
	Tags         []string          `json:"tags" db:"tags"`
	ExpiryDate   *time.Time        `json:"expiry_date,omitempty" db:"expiry_date"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at" db:"updated_at"`
	Version      int64             `json:"version" db:"version"`
	Metadata     map[string]string `json:"metadata,omitempty" db:"metadata"`
}

// SecretMeta represents secret metadata without sensitive data.
type SecretMeta struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Scope      string            `json:"scope"`
	Category   string            `json:"category"`
	Tags       []string          `json:"tags"`
	ExpiryDate *time.Time        `json:"expiry_date,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Version    int64             `json:"version"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// SecretFilter provides filtering options for listing secrets.
type SecretFilter struct {
	Scope      string    `json:"scope,omitempty"`
	Category   string    `json:"category,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	ExpiredOnly   bool      `json:"expired_only,omitempty"`
	ActiveOnly    bool      `json:"active_only,omitempty"`
	Limit         int       `json:"limit,omitempty"`
	Offset        int       `json:"offset,omitempty"`
	SortBy        string    `json:"sort_by,omitempty"` // name, created_at, updated_at
	SortOrder     string    `json:"sort_order,omitempty"` // asc, desc
}

// AuditLog represents an audit log entry.
type AuditLog struct {
	ID               int64             `json:"id" db:"id"`
	SecretID         *string           `json:"secret_id,omitempty" db:"secret_id"`
	Operation        string            `json:"operation" db:"operation"`
	UserID           string            `json:"user_id" db:"user_id"`
	DeviceID         string            `json:"device_id" db:"device_id"`
	ClientIP         *string           `json:"client_ip,omitempty" db:"client_ip"`
	UserAgent        *string           `json:"user_agent,omitempty" db:"user_agent"`
	OperationDetails map[string]string `json:"operation_details,omitempty" db:"operation_details"`
	Success          bool              `json:"success" db:"success"`
	ErrorMessage     *string           `json:"error_message,omitempty" db:"error_message"`
	Timestamp        time.Time         `json:"timestamp" db:"timestamp"`
	SessionID        *string           `json:"session_id,omitempty" db:"session_id"`
}

// AuditFilter provides filtering options for audit logs.
type AuditFilter struct {
	SecretID     *string    `json:"secret_id,omitempty"`
	UserID       *string    `json:"user_id,omitempty"`
	DeviceID     *string    `json:"device_id,omitempty"`
	Operation    *string    `json:"operation,omitempty"`
	SuccessOnly  *bool      `json:"success_only,omitempty"`
	FailuresOnly *bool      `json:"failures_only,omitempty"`
	Since        *time.Time `json:"since,omitempty"`
	Until        *time.Time `json:"until,omitempty"`
	Limit        int        `json:"limit,omitempty"`
	Offset       int        `json:"offset,omitempty"`
}

// Device represents a registered device.
type Device struct {
	ID           string            `json:"id" db:"id"`
	UserID       string            `json:"user_id" db:"user_id"`
	DeviceName   string            `json:"device_name" db:"device_name"`
	DeviceType   string            `json:"device_type" db:"device_type"`
	PublicKey    *string           `json:"public_key,omitempty" db:"public_key"`
	Fingerprint  *string           `json:"fingerprint,omitempty" db:"fingerprint"`
	Platform     *string           `json:"platform,omitempty" db:"platform"`
	AppVersion   *string           `json:"app_version,omitempty" db:"app_version"`
	LastUsedAt   *time.Time        `json:"last_used_at,omitempty" db:"last_used_at"`
	RegisteredAt time.Time         `json:"registered_at" db:"registered_at"`
	IsActive     bool              `json:"is_active" db:"is_active"`
	TrustLevel   string            `json:"trust_level" db:"trust_level"`
	Metadata     map[string]string `json:"metadata,omitempty" db:"metadata"`
}

// StoreStats provides statistics about the store.
type StoreStats struct {
	SecretCount       int64     `json:"secret_count"`
	AuditLogCount     int64     `json:"audit_log_count"`
	DeviceCount       int64     `json:"device_count"`
	ActiveDeviceCount int64     `json:"active_device_count"`
	ExpiredSecretCount int64    `json:"expired_secret_count"`
	DatabaseSize      int64     `json:"database_size,omitempty"` // in bytes
	LastBackup        *time.Time `json:"last_backup,omitempty"`
	Health            string    `json:"health"` // healthy, degraded, unhealthy
}

// Common operation types for audit logging.
const (
	// Secret operations
	OpCreateSecret = "CREATE_SECRET"
	OpReadSecret   = "READ_SECRET"
	OpUpdateSecret = "UPDATE_SECRET"
	OpDeleteSecret = "DELETE_SECRET"
	OpListSecrets  = "LIST_SECRETS"
	
	// Authentication operations
	OpLogin        = "LOGIN"
	OpLogout       = "LOGOUT"
	OpRefreshToken = "REFRESH_TOKEN"
	OpRevokeToken  = "REVOKE_TOKEN"
	
	// Device operations
	OpRegisterDevice   = "REGISTER_DEVICE"
	OpDeactivateDevice = "DEACTIVATE_DEVICE"
	OpUpdateDevice     = "UPDATE_DEVICE"
	
	// Administrative operations
	OpExportSecrets = "EXPORT_SECRETS"
	OpImportSecrets = "IMPORT_SECRETS"
	OpBackupDatabase = "BACKUP_DATABASE"
	OpRestoreDatabase = "RESTORE_DATABASE"
)

// Common scopes for secrets.
const (
	ScopeUser   = "user"     // User-specific secrets
	ScopeSystem = "system"   // System-wide secrets
	ScopeShared = "shared"   // Shared between users
	ScopePublic = "public"   // Public information (limited encryption)
)

// Common categories for secrets.
const (
	CategoryGeneral     = "general"
	CategoryPassword    = "password"
	CategoryAPIKey      = "api_key"
	CategoryCertificate = "certificate"
	CategorySSHKey      = "ssh_key"
	CategoryNote        = "note"
	CategoryFile        = "file"
	CategoryToken       = "token"
	CategoryDatabase    = "database"
	CategoryAWS         = "aws"
	CategoryCloudflare  = "cloudflare"
	CategoryGitHub      = "github"
)

// Device types.
const (
	DeviceTypeDesktop = "desktop"
	DeviceTypeMobile  = "mobile"
	DeviceTypeWeb     = "web"
	DeviceTypeCLI     = "cli"
	DeviceTypeServer  = "server"
	DeviceTypeUnknown = "unknown"
)

// Trust levels for devices.
const (
	TrustLevelUntrusted = "untrusted"
	TrustLevelLimited   = "limited"
	TrustLevelTrusted   = "trusted"
	TrustLevelFull      = "full"
)

// Validation functions

// IsValidScope checks if the scope is valid.
func IsValidScope(scope string) bool {
	switch scope {
	case ScopeUser, ScopeSystem, ScopeShared, ScopePublic:
		return true
	default:
		return false
	}
}

// IsValidCategory checks if the category is valid.
func IsValidCategory(category string) bool {
	switch category {
	case CategoryGeneral, CategoryPassword, CategoryAPIKey, CategoryCertificate,
		 CategorySSHKey, CategoryNote, CategoryFile, CategoryToken, CategoryDatabase,
		 CategoryAWS, CategoryCloudflare, CategoryGitHub:
		return true
	default:
		return false
	}
}

// IsValidDeviceType checks if the device type is valid.
func IsValidDeviceType(deviceType string) bool {
	switch deviceType {
	case DeviceTypeDesktop, DeviceTypeMobile, DeviceTypeWeb, DeviceTypeCLI, DeviceTypeServer, DeviceTypeUnknown:
		return true
	default:
		return false
	}
}

// IsValidTrustLevel checks if the trust level is valid.
func IsValidTrustLevel(trustLevel string) bool {
	switch trustLevel {
	case TrustLevelUntrusted, TrustLevelLimited, TrustLevelTrusted, TrustLevelFull:
		return true
	default:
		return false
	}
}