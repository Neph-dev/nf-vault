// Package local provides a local client for direct SQLite database operations
package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
	"github.com/Neph-dev/nef-vault/pkg/admin"
	"github.com/Neph-dev/nef-vault/pkg/crypto"
	"github.com/Neph-dev/nef-vault/pkg/store"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// LocalClient provides direct access to local SQLite operations
type LocalClient struct {
	store       store.Store
	adminCheck  *admin.Checker
	dataDir     string
	masterKey   []byte // In-memory master key for encryption
}

// Config holds configuration for the local client
type Config struct {
	DataDir string // Directory to store the vault database
}

// NewLocalClient creates a new local client instance
func NewLocalClient(config *Config) (*LocalClient, error) {
	adminCheck := admin.NewChecker()
	
	// Use default data directory if not specified
	dataDir := config.DataDir
	if dataDir == "" {
		homeDir, err := adminCheck.GetUserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dataDir = filepath.Join(homeDir, ".nef-vault")
	}

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create SQLite store
	dbPath := filepath.Join(dataDir, "vault.db")
	sqliteStore, err := store.NewSQLiteStore(dbPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create SQLite store: %w", err)
	}

	return &LocalClient{
		store:      sqliteStore,
		adminCheck: adminCheck,
		dataDir:    dataDir,
	}, nil
}

// RequireAdmin checks if the current user has admin privileges
func (c *LocalClient) RequireAdmin() error {
	return c.adminCheck.RequireAdmin()
}

// Close closes the local client and its database connection
func (c *LocalClient) Close() error {
	return c.store.Close()
}

// GetMasterKey returns the master key, creating it if necessary
func (c *LocalClient) GetMasterKey(passphrase string) ([]byte, error) {
	if c.masterKey != nil {
		return c.masterKey, nil
	}
	
	// Try to get existing salt from system secret
	ctx := context.Background()
	systemSecret, err := c.store.GetSecretByID(ctx, "system:kdf_salt")
	
	var masterKey []byte
	if err != nil {
		// First time setup - create new salt and master key
		salt, err := crypto.GenerateSalt(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}

		kdfParams := crypto.DefaultKDFParams()
		masterKey, err = crypto.DeriveKey([]byte(passphrase), salt, kdfParams)
		if err != nil {
			return nil, fmt.Errorf("failed to derive master key: %w", err)
		}

		// Store salt for future use
		saltSecret := &store.Secret{
			ID:            "system:kdf_salt",
			Name:          "system:kdf_salt",
			EncryptedKey:  make([]byte, 0), // Empty since salt doesn't need encryption
			EncryptedData: salt,
			Scope:         store.ScopeSystem,
			Category:      store.CategoryNote,
			Version:       1,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := c.store.CreateSecret(ctx, saltSecret); err != nil {
			return nil, fmt.Errorf("failed to store salt: %w", err)
		}
	} else {
		// Existing setup - derive key from stored salt
		salt := systemSecret.EncryptedData
		kdfParams := crypto.DefaultKDFParams()
		masterKey, err = crypto.DeriveKey([]byte(passphrase), salt, kdfParams)
		if err != nil {
			return nil, fmt.Errorf("failed to derive master key: %w", err)
		}
	}
	
	c.masterKey = masterKey
	return masterKey, nil
}

// CreateSecret creates a new secret in the local vault
func (c *LocalClient) CreateSecret(ctx context.Context, secret *vault.Secret, data []byte) (*vault.Secret, error) {
	if err := c.RequireAdmin(); err != nil {
		return nil, err
	}
	
	// Generate unique ID
	secretID := uuid.New().String()
	
	// Store data in plain text (no encryption since it's local admin-only)
	
	// Convert vault.Secret to store.Secret
	storeSecret := &store.Secret{
		ID:            secretID,
		Name:          secret.Name,
		EncryptedKey:  make([]byte, 0),   // Empty since we're not using encryption
		EncryptedData: data,              // Store data directly
		Scope:         store.ScopeUser,   // Default scope
		Category:      store.CategoryPassword, // Default category
		Version:       1, // Database row version starts at 1
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	
	if secret.Metadata != nil {
		if secret.Metadata.Category != "" {
			storeSecret.Category = secret.Metadata.Category
		}
		// Store metadata as JSON in the store
		storeSecret.Tags = secret.Metadata.Tags
	}
	
	// Save to store
	if err := c.store.CreateSecret(ctx, storeSecret); err != nil {
		return nil, fmt.Errorf("failed to store secret: %w", err)
	}
	
	// Return created secret
	result := &vault.Secret{
		Id:        secretID,
		Name:      secret.Name,
		CreatedAt: timestamppb.New(storeSecret.CreatedAt),
		UpdatedAt: timestamppb.New(storeSecret.UpdatedAt),
		Metadata:  secret.Metadata,
	}
	
	return result, nil
}

// GetSecret retrieves a secret from the local vault
func (c *LocalClient) GetSecret(ctx context.Context, identifier string, includeData bool) (*vault.Secret, []byte, error) {
	if err := c.RequireAdmin(); err != nil {
		return nil, nil, err
	}
	
	// Try to get by ID first, then by name
	var storeSecret *store.Secret
	var err error
	
	storeSecret, err = c.store.GetSecretByID(ctx, identifier)
	if err != nil {
		// Try by name
		storeSecret, err = c.store.GetSecret(ctx, identifier)
		if err != nil {
			return nil, nil, fmt.Errorf("secret not found: %w", err)
		}
	}
	
	// Convert to vault.Secret
	result := &vault.Secret{
		Id:        storeSecret.ID,
		Name:      storeSecret.Name,
		CreatedAt: timestamppb.New(storeSecret.CreatedAt),
		UpdatedAt: timestamppb.New(storeSecret.UpdatedAt),
		Metadata: &vault.SecretMetadata{
		Category:  storeSecret.Category,
			Tags:     storeSecret.Tags,
		},
	}
	
	var data []byte
	if includeData {
		// Return data directly (no decryption needed since we're storing in plain text)
		data = storeSecret.EncryptedData
	}
	
	return result, data, nil
}

// UpdateSecret updates an existing secret in the local vault
func (c *LocalClient) UpdateSecret(ctx context.Context, secret *vault.Secret, data []byte) (*vault.Secret, error) {
	if err := c.RequireAdmin(); err != nil {
		return nil, err
	}
	
	// Get existing secret by ID first, then by name
	var existing *store.Secret
	var err error
	
	existing, err = c.store.GetSecretByID(ctx, secret.Id)
	if err != nil {
		// Try by name
		existing, err = c.store.GetSecret(ctx, secret.Name)
		if err != nil {
			return nil, fmt.Errorf("secret not found: %w", err)
		}
	}
	
	// Update fields
	existing.Name = secret.Name
	existing.UpdatedAt = time.Now()
	
	if secret.Metadata != nil {
		if secret.Metadata.Category != "" {
			existing.Category = secret.Metadata.Category
		}
		existing.Tags = secret.Metadata.Tags
	}
	
	// Update data if provided (store in plain text)
	if data != nil {
		existing.EncryptedKey = make([]byte, 0) // Empty since we're not using encryption
		existing.EncryptedData = data          // Store data directly
	}
	
	// Update the secret in storage
	if err := c.store.UpdateSecret(ctx, existing); err != nil {
		return nil, fmt.Errorf("failed to update secret: %w", err)
	}
	
	// Return updated secret
	result := &vault.Secret{
		Id:        existing.ID,
		Name:      existing.Name,
		CreatedAt: timestamppb.New(existing.CreatedAt),
		UpdatedAt: timestamppb.New(existing.UpdatedAt),
		Metadata: &vault.SecretMetadata{
			Category: string(existing.Category),
			Tags:     existing.Tags,
		},
	}
	
	return result, nil
}

// DeleteSecret deletes a secret from the local vault
func (c *LocalClient) DeleteSecret(ctx context.Context, identifier string) error {
	if err := c.RequireAdmin(); err != nil {
		return err
	}
	
	// Try to delete by ID first, then by name
	err := c.store.DeleteSecret(ctx, identifier)
	if err != nil {
		// Try to get by ID first to get the name, then delete by name
		secret, getErr := c.store.GetSecretByID(ctx, identifier)
		if getErr != nil {
			return fmt.Errorf("secret not found: %w", err)
		}
		err = c.store.DeleteSecret(ctx, secret.Name)
		if err != nil {
			return fmt.Errorf("failed to delete secret: %w", err)
		}
	}
	
	return nil
}

// ListSecrets lists secrets in the local vault
func (c *LocalClient) ListSecrets(ctx context.Context, limit int32, cursor string) ([]*vault.Secret, string, error) {
	if err := c.RequireAdmin(); err != nil {
		return nil, "", err
	}
	
	filter := &store.SecretFilter{
		Limit: int(limit),
	}
	
	secretMetas, err := c.store.ListSecrets(ctx, filter)
	if err != nil {
		return nil, "", fmt.Errorf("failed to list secrets: %w", err)
	}
	
	var results []*vault.Secret
	for _, meta := range secretMetas {
		secret := &vault.Secret{
			Id:        meta.ID,
			Name:      meta.Name,
			CreatedAt: timestamppb.New(meta.CreatedAt),
			UpdatedAt: timestamppb.New(meta.UpdatedAt),
			Metadata: &vault.SecretMetadata{
				Category: string(meta.Category),
				Tags:     meta.Tags,
			},
		}
		results = append(results, secret)
	}
	
	return results, "", nil
}

// Ping tests the connection to the local store
func (c *LocalClient) Ping(ctx context.Context) error {
	return c.store.Ping(ctx)
}
