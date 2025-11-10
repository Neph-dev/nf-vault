package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
)

// VaultClientConfig holds configuration for the vault client
type VaultClientConfig struct {
	ServerAddr         string
	TLSEnabled         bool
	InsecureSkipVerify bool
	Timeout            time.Duration
	TokenStore         TokenStore
}

// DefaultClientConfig returns a default client configuration
func DefaultClientConfig() *VaultClientConfig {
	tokenStore, _ := DefaultTokenStore()
	return &VaultClientConfig{
		ServerAddr:         "localhost:8443",
		TLSEnabled:         true,
		InsecureSkipVerify: false,
		Timeout:            30 * time.Second,
		TokenStore:         tokenStore,
	}
}

// VaultClient provides a high-level interface to the nef-vault server
type VaultClient struct {
	config     *VaultClientConfig
	conn       *grpc.ClientConn
	client     vault.VaultServiceClient
	tokenStore TokenStore
}

// NewVaultClient creates a new vault client with the given configuration
func NewVaultClient(config *VaultClientConfig) (*VaultClient, error) {
	if config == nil {
		config = DefaultClientConfig()
	}

	// Create gRPC dial options
	var opts []grpc.DialOption

	// Configure TLS
	if config.TLSEnabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Add timeout
	if config.Timeout > 0 {
		opts = append(opts, grpc.WithTimeout(config.Timeout))
	}

	// Connect to server
	conn, err := grpc.Dial(config.ServerAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	client := vault.NewVaultServiceClient(conn)

	return &VaultClient{
		config:     config,
		conn:       conn,
		client:     client,
		tokenStore: config.TokenStore,
	}, nil
}

// Close closes the client connection
func (v *VaultClient) Close() error {
	if v.conn != nil {
		return v.conn.Close()
	}
	return nil
}

// authenticatedContext creates a context with authentication token
func (v *VaultClient) authenticatedContext(ctx context.Context) (context.Context, error) {
	if v.tokenStore == nil {
		return nil, fmt.Errorf("no token store configured")
	}

	token, err := v.tokenStore.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load token: %w", err)
	}

	// Check if token is expired and try to refresh if possible
	if time.Now().After(token.ExpiresAt.Add(-5 * time.Minute)) {
		if token.RefreshToken != "" {
			newToken, err := v.refreshToken(ctx, token.RefreshToken)
			if err != nil {
				return nil, fmt.Errorf("token expired and refresh failed: %w", err)
			}
			token = newToken
		} else {
			return nil, fmt.Errorf("token expired and no refresh token available")
		}
	}

	// Add token to metadata
	md := metadata.Pairs("authorization", "Bearer "+token.AccessToken)
	return metadata.NewOutgoingContext(ctx, md), nil
}

// refreshToken automatically refreshes an expired token
func (v *VaultClient) refreshToken(ctx context.Context, refreshToken string) (*TokenInfo, error) {
	req := &vault.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	resp, err := v.client.RefreshToken(ctx, req)
	if err != nil {
		return nil, err
	}

	// Create new token info
	newToken := &TokenInfo{
		AccessToken:  resp.Token,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt.AsTime(),
		DeviceID:     "", // This should be preserved from old token
		ServerAddr:   v.config.ServerAddr,
	}

	// Store the new token
	if err := v.tokenStore.Store(newToken); err != nil {
		return nil, fmt.Errorf("failed to store refreshed token: %w", err)
	}

	return newToken, nil
}

// Authenticate performs authentication with the server
func (v *VaultClient) Authenticate(ctx context.Context, deviceID, passphrase string) (*TokenInfo, error) {
	// Create device info for registration
	deviceInfo := &vault.DeviceInfo{
		Name:       deviceID,
		Os:         "cli",
		AppVersion: "1.0.0",
		UserAgent:  "nfvault-cli/1.0.0",
	}

	req := &vault.AuthenticateRequest{
		DeviceId:   deviceID,
		Passphrase: passphrase,
		DeviceInfo: deviceInfo,
	}

	resp, err := v.client.Authenticate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Create token info
	token := &TokenInfo{
		AccessToken:  resp.Token,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt.AsTime(),
		DeviceID:     deviceID,
		ServerAddr:   v.config.ServerAddr,
	}

	// Store token
	if v.tokenStore != nil {
		if err := v.tokenStore.Store(token); err != nil {
			return nil, fmt.Errorf("failed to store token: %w", err)
		}
	}

	return token, nil
}

// CreateSecret creates a new secret
func (v *VaultClient) CreateSecret(ctx context.Context, secret *vault.Secret, plaintextData []byte) (*vault.Secret, error) {
	authCtx, err := v.authenticatedContext(ctx)
	if err != nil {
		return nil, err
	}

	req := &vault.CreateSecretRequest{
		Secret:        secret,
		PlaintextData: plaintextData,
	}

	resp, err := v.client.CreateSecret(authCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	return resp.Secret, nil
}

// GetSecret retrieves a secret by name or ID
func (v *VaultClient) GetSecret(ctx context.Context, identifier string, includeData bool) (*vault.Secret, []byte, error) {
	authCtx, err := v.authenticatedContext(ctx)
	if err != nil {
		return nil, nil, err
	}

	req := &vault.GetSecretRequest{
		Identifier:  identifier,
		IncludeData: includeData,
	}

	resp, err := v.client.GetSecret(authCtx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get secret: %w", err)
	}

	return resp.Secret, resp.DecryptedData, nil
}

// UpdateSecret updates an existing secret
func (v *VaultClient) UpdateSecret(ctx context.Context, secret *vault.Secret, plaintextData []byte) (*vault.Secret, error) {
	authCtx, err := v.authenticatedContext(ctx)
	if err != nil {
		return nil, err
	}

	req := &vault.UpdateSecretRequest{
		Secret:        secret,
		PlaintextData: plaintextData,
	}

	resp, err := v.client.UpdateSecret(authCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update secret: %w", err)
	}

	return resp.Secret, nil
}

// DeleteSecret deletes a secret by ID
func (v *VaultClient) DeleteSecret(ctx context.Context, secretID string) error {
	authCtx, err := v.authenticatedContext(ctx)
	if err != nil {
		return err
	}

	req := &vault.DeleteSecretRequest{
		Id: secretID,
	}

	_, err = v.client.DeleteSecret(authCtx, req)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

// ListSecrets lists secrets with optional filtering
func (v *VaultClient) ListSecrets(ctx context.Context, pageSize int32, pageToken string) ([]*vault.Secret, string, error) {
	authCtx, err := v.authenticatedContext(ctx)
	if err != nil {
		return nil, "", err
	}

	req := &vault.ListSecretsRequest{
		PageSize:  pageSize,
		PageToken: pageToken,
	}

	resp, err := v.client.ListSecrets(authCtx, req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to list secrets: %w", err)
	}

	return resp.Secrets, resp.NextPageToken, nil
}

// GetAuditLog retrieves audit log entries
func (v *VaultClient) GetAuditLog(ctx context.Context, pageSize int32, pageToken string) ([]*vault.AuditEntry, string, error) {
	authCtx, err := v.authenticatedContext(ctx)
	if err != nil {
		return nil, "", err
	}

	req := &vault.GetAuditLogRequest{
		PageSize:  pageSize,
		PageToken: pageToken,
	}

	resp, err := v.client.GetAuditLog(authCtx, req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get audit log: %w", err)
	}

	return resp.Entries, resp.NextPageToken, nil
}

// GetVaultInfo retrieves vault information and status
func (v *VaultClient) GetVaultInfo(ctx context.Context) (*vault.GetVaultInfoResponse, error) {
	authCtx, err := v.authenticatedContext(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := v.client.GetVaultInfo(authCtx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to get vault info: %w", err)
	}

	return resp, nil
}

// Health checks server health
func (v *VaultClient) Health(ctx context.Context) (*vault.HealthResponse, error) {
	// Health check doesn't require authentication
	resp, err := v.client.Health(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}

	return resp, nil
}

// RevokeToken revokes the current or specified token
func (v *VaultClient) RevokeToken(ctx context.Context, token *string) error {
	authCtx, err := v.authenticatedContext(ctx)
	if err != nil {
		return err
	}

	req := &vault.RevokeTokenRequest{
		Token: token,
	}

	_, err = v.client.RevokeToken(authCtx, req)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	// Clear local token if revoking current token
	if token == nil && v.tokenStore != nil {
		v.tokenStore.Clear()
	}

	return nil
}

// Logout clears the stored token and optionally revokes it on the server
func (v *VaultClient) Logout(ctx context.Context, revokeOnServer bool) error {
	if revokeOnServer {
		// Try to revoke on server, but don't fail if it doesn't work
		v.RevokeToken(ctx, nil)
	}

	// Clear local token
	if v.tokenStore != nil {
		return v.tokenStore.Clear()
	}

	return nil
}

// IsAuthenticated checks if the client has a valid token
func (v *VaultClient) IsAuthenticated() bool {
	if v.tokenStore == nil {
		return false
	}
	return v.tokenStore.IsValid()
}