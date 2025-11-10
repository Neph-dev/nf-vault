// Package client provides client-side utilities for interacting with the nef-vault server.
package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// TokenInfo represents stored authentication information
type TokenInfo struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	DeviceID     string    `json:"device_id"`
	ServerAddr   string    `json:"server_addr"`
	StoredAt     time.Time `json:"stored_at"`
}

// TokenStore handles secure storage and retrieval of authentication tokens
type TokenStore interface {
	Store(token *TokenInfo) error
	Load() (*TokenInfo, error)
	Clear() error
	IsValid() bool
}

// FileTokenStore implements TokenStore using the filesystem
type FileTokenStore struct {
	configDir string
	tokenFile string
}

// NewFileTokenStore creates a new filesystem-based token store
func NewFileTokenStore() (*FileTokenStore, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get config directory: %w", err)
	}

	tokenFile := filepath.Join(configDir, "token")

	return &FileTokenStore{
		configDir: configDir,
		tokenFile: tokenFile,
	}, nil
}

// Store saves the token information to the filesystem with secure permissions
func (f *FileTokenStore) Store(token *TokenInfo) error {
	// Ensure config directory exists
	if err := os.MkdirAll(f.configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Set storage timestamp
	token.StoredAt = time.Now()

	// Marshal token to JSON
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	// Write to temporary file first for atomic operation
	tempFile := f.tokenFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempFile, f.tokenFile); err != nil {
		os.Remove(tempFile) // Clean up temp file
		return fmt.Errorf("failed to rename token file: %w", err)
	}

	return nil
}

// Load retrieves the stored token information
func (f *FileTokenStore) Load() (*TokenInfo, error) {
	data, err := os.ReadFile(f.tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no token found, please login first")
		}
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var token TokenInfo
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token file: %w", err)
	}

	return &token, nil
}

// Clear removes the stored token
func (f *FileTokenStore) Clear() error {
	if err := os.Remove(f.tokenFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove token file: %w", err)
	}
	return nil
}

// IsValid checks if a stored token exists and is not expired
func (f *FileTokenStore) IsValid() bool {
	token, err := f.Load()
	if err != nil {
		return false
	}

	// Check if token is expired (with 5 minute buffer)
	return time.Now().Before(token.ExpiresAt.Add(-5 * time.Minute))
}

// GetTokenFile returns the path to the token file (useful for debugging/info)
func (f *FileTokenStore) GetTokenFile() string {
	return f.tokenFile
}

// getConfigDir returns the appropriate configuration directory for the current OS
func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	var configDir string
	switch runtime.GOOS {
	case "darwin":
		// macOS: ~/Library/Application Support/nfvault
		configDir = filepath.Join(homeDir, "Library", "Application Support", "nfvault")
	case "windows":
		// Windows: %APPDATA%/nfvault
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(homeDir, "AppData", "Roaming")
		}
		configDir = filepath.Join(appData, "nfvault")
	default:
		// Linux/Unix: ~/.config/nfvault or ~/.nfvault
		if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
			configDir = filepath.Join(xdgConfig, "nfvault")
		} else {
			configDir = filepath.Join(homeDir, ".config", "nfvault")
		}
	}

	return configDir, nil
}

// KeyringTokenStore implements TokenStore using the OS keyring (optional enhancement)
type KeyringTokenStore struct {
	serviceName string
	accountName string
}

// NewKeyringTokenStore creates a new keyring-based token store
// Note: This requires the keyring library to be implemented
func NewKeyringTokenStore() (*KeyringTokenStore, error) {
	return &KeyringTokenStore{
		serviceName: "nef-vault",
		accountName: "default",
	}, nil
}

// Store saves the token to the OS keyring
func (k *KeyringTokenStore) Store(token *TokenInfo) error {
	// This would require implementing keyring integration
	// For now, fall back to file storage
	fileStore, err := NewFileTokenStore()
	if err != nil {
		return err
	}
	return fileStore.Store(token)
}

// Load retrieves the token from the OS keyring
func (k *KeyringTokenStore) Load() (*TokenInfo, error) {
	// This would require implementing keyring integration
	// For now, fall back to file storage
	fileStore, err := NewFileTokenStore()
	if err != nil {
		return nil, err
	}
	return fileStore.Load()
}

// Clear removes the token from the OS keyring
func (k *KeyringTokenStore) Clear() error {
	// This would require implementing keyring integration
	// For now, fall back to file storage
	fileStore, err := NewFileTokenStore()
	if err != nil {
		return err
	}
	return fileStore.Clear()
}

// IsValid checks if the stored token is valid
func (k *KeyringTokenStore) IsValid() bool {
	// This would require implementing keyring integration
	// For now, fall back to file storage
	fileStore, err := NewFileTokenStore()
	if err != nil {
		return false
	}
	return fileStore.IsValid()
}

// DefaultTokenStore returns the default token store for the current platform
func DefaultTokenStore() (TokenStore, error) {
	// For now, always use file storage
	// In the future, this could detect keyring availability and prefer it
	return NewFileTokenStore()
}