package server_test

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
	"github.com/Neph-dev/nef-vault/internal/server"
	"github.com/Neph-dev/nef-vault/pkg/store"
)

const bufSize = 1024 * 1024

var (
	testDataDir = "/tmp/nef-vault-test"
	testDBPath  = filepath.Join(testDataDir, "test.db")
)

// createTestTables creates the necessary tables for testing by directly executing SQL
func createTestTables(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()
	
	// Create the basic schema that matches what the store expects
	schema := `
	CREATE TABLE IF NOT EXISTS secrets (
		id VARCHAR(255) PRIMARY KEY,
		name VARCHAR(255) NOT NULL UNIQUE,
		encrypted_key BLOB NOT NULL,
		encrypted_data BLOB NOT NULL,
		scope VARCHAR(100) NOT NULL DEFAULT 'global',
		category VARCHAR(100) DEFAULT '',
		tags TEXT DEFAULT '[]',
		expiry_date DATETIME NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		version INTEGER NOT NULL DEFAULT 1,
		metadata TEXT DEFAULT '{}'
	);
	
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		secret_id VARCHAR(255),
		operation VARCHAR(100) NOT NULL,
		user_id VARCHAR(255),
		device_id VARCHAR(255),
		client_ip VARCHAR(45),
		user_agent TEXT,
		operation_details TEXT DEFAULT '{}',
		success BOOLEAN NOT NULL DEFAULT TRUE,
		error_message TEXT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		session_id VARCHAR(255)
	);
	
	CREATE TABLE IF NOT EXISTS devices (
		id VARCHAR(255) PRIMARY KEY,
		user_id VARCHAR(255) NOT NULL,
		device_name VARCHAR(255) NOT NULL,
		device_type VARCHAR(100) NOT NULL,
		public_key TEXT NOT NULL,
		fingerprint VARCHAR(255) NOT NULL UNIQUE,
		platform VARCHAR(100),
		app_version VARCHAR(100),
		last_used_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		is_active BOOLEAN NOT NULL DEFAULT TRUE,
		trust_level VARCHAR(50) NOT NULL DEFAULT 'basic',
		metadata TEXT DEFAULT '{}'
	);`
	
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	
	return nil
}

// TestServer represents a test server instance
type TestServer struct {
	listener    *bufconn.Listener
	server      *grpc.Server
	store       store.Store
	authService *server.AuthService
	conn        *grpc.ClientConn
	client      vault.VaultServiceClient
	cleanup     func()
}

// NewTestServer creates a new test server instance
func NewTestServer(t *testing.T, enableTLS bool) *TestServer {
	// Cleanup any existing test data
	os.RemoveAll(testDataDir)
	
	// Create test data directory
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		t.Fatalf("Failed to create test data directory: %v", err)
	}
	
	// Create tables manually for testing before creating the store
	if err := createTestTables(testDBPath); err != nil {
		t.Fatalf("Failed to create test tables: %v", err)
	}
	
	// Create SQLite store for testing using file database with pre-created tables
	testStore, err := store.NewSQLiteStore(testDBPath, "")
	if err != nil {
		t.Fatalf("Failed to create test store: %v", err)
	}
	
	// Create auth service
	authConfig := server.AuthServiceConfig{
		Store:           testStore,
		JWTSecret:       []byte("test-jwt-secret-key-12345"),
		TokenLifetime:   time.Hour,
		RefreshLifetime: 2 * time.Hour,
	}
	authService := server.NewAuthService(authConfig)
	
	// Create interceptors
	authInterceptor := server.NewAuthInterceptor(authService)
	testLogger := log.New(os.Stderr, "[test] ", log.LstdFlags)
	loggingInterceptor := server.NewLoggingInterceptor(testLogger)
	errorInterceptor := server.NewErrorHandlingInterceptor()
	
	// Create server options
	var opts []grpc.ServerOption
	
	// Add TLS if requested
	if enableTLS {
		// Create self-signed certificate for testing
		certInfo := server.DefaultCertificateInfo()
		cert, key, err := server.GenerateSelfSignedCertificate(certInfo)
		if err != nil {
			t.Fatalf("Failed to generate test certificate: %v", err)
		}
		
		certFile := filepath.Join(testDataDir, "server.crt")
		keyFile := filepath.Join(testDataDir, "server.key")
		
		if err := server.SaveCertificateAndKey(cert, key, certFile, keyFile); err != nil {
			t.Fatalf("Failed to save test certificate: %v", err)
		}
		
		tlsConfig := &server.TLSConfig{
			CertFile:           certFile,
			KeyFile:            keyFile,
			ServerName:         "localhost",
			RequireClientCert:  false,
			InsecureSkipVerify: true, // For testing
		}
		
		serverTLS, err := server.LoadTLSConfig(tlsConfig)
		if err != nil {
			t.Fatalf("Failed to load TLS config: %v", err)
		}
		
		creds := credentials.NewTLS(serverTLS)
		opts = append(opts, grpc.Creds(creds))
	}
	
	// Add interceptors
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			loggingInterceptor.UnaryInterceptor,
			authInterceptor.UnaryInterceptor,
			errorInterceptor.UnaryInterceptor,
		),
		grpc.ChainStreamInterceptor(
			loggingInterceptor.StreamInterceptor,
			authInterceptor.StreamInterceptor,
			errorInterceptor.StreamInterceptor,
		),
	)
	
	// Create gRPC server
	grpcServer := grpc.NewServer(opts...)
	
	// Register vault service
	vaultService := server.NewVaultServiceServer(testStore, authService)
	vault.RegisterVaultServiceServer(grpcServer, vaultService)
	
	// Create in-memory listener
	listener := bufconn.Listen(bufSize)
	
	// Start server
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()
	
	// Create client connection
	var dialOpts []grpc.DialOption
	
	// Add dialer for bufconn first
	dialOpts = append(dialOpts, grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	
	if enableTLS {
		// For testing, use insecure TLS
		clientTLS := &tls.Config{InsecureSkipVerify: true}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	
	conn, err := grpc.Dial("bufnet", dialOpts...)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	
	client := vault.NewVaultServiceClient(conn)
	
	cleanup := func() {
		conn.Close()
		grpcServer.Stop()
		testStore.Close()
		os.RemoveAll(testDataDir)
	}
	
	return &TestServer{
		listener:    listener,
		server:      grpcServer,
		store:       testStore,
		authService: authService,
		conn:        conn,
		client:      client,
		cleanup:     cleanup,
	}
}

// authenticateDevice helper function to authenticate a test device
func (ts *TestServer) authenticateDevice(t *testing.T, deviceID, passphrase string) string {
	req := &vault.AuthenticateRequest{
		DeviceId:   deviceID,
		Passphrase: passphrase,
	}
	
	resp, err := ts.client.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}
	
	if resp.Token == "" {
		t.Fatal("Expected non-empty token")
	}
	
	return resp.Token
}

// createAuthenticatedContext creates a context with authentication token
func createAuthenticatedContext(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(context.Background(), md)
}

func TestServerIntegration(t *testing.T) {
	t.Run("WithoutTLS", func(t *testing.T) {
		testServer := NewTestServer(t, false)
		defer testServer.cleanup()
		
		runIntegrationTests(t, testServer)
	})
	
	t.Run("WithTLS", func(t *testing.T) {
		testServer := NewTestServer(t, true)
		defer testServer.cleanup()
		
		runIntegrationTests(t, testServer)
	})
}

func runIntegrationTests(t *testing.T, ts *TestServer) {
	const (
		deviceID   = "test-device-1"
		passphrase = "test-passphrase-123"
	)
	
	t.Run("Authentication", func(t *testing.T) {
		testAuthentication(t, ts, deviceID, passphrase)
	})
	
	// Get authentication token for subsequent tests
	token := ts.authenticateDevice(t, deviceID, passphrase)
	authCtx := createAuthenticatedContext(token)
	
	t.Run("SecretCRUD", func(t *testing.T) {
		testSecretCRUD(t, ts, authCtx)
	})
	
	t.Run("SecretListing", func(t *testing.T) {
		testSecretListing(t, ts, authCtx)
	})
	
	t.Run("AuditLogging", func(t *testing.T) {
		testAuditLogging(t, ts, authCtx)
	})
	
	t.Run("ErrorHandling", func(t *testing.T) {
		testErrorHandling(t, ts, authCtx)
	})
	
	t.Run("TokenManagement", func(t *testing.T) {
		testTokenManagement(t, ts, deviceID, passphrase)
	})
}

func testAuthentication(t *testing.T, ts *TestServer, deviceID, passphrase string) {
	// Test first-time authentication (device registration)
	req := &vault.AuthenticateRequest{
		DeviceId:   deviceID,
		Passphrase: passphrase,
	}
	
	resp, err := ts.client.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}
	
	if resp.Token == "" {
		t.Error("Expected non-empty token")
	}
	
	if resp.ExpiresAt == nil {
		t.Error("Expected valid token expiration")
	}
	
	// Test authentication with same credentials (should work)
	resp2, err := ts.client.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Re-authentication failed: %v", err)
	}
	
	if resp2.Token == "" {
		t.Error("Expected non-empty token on re-authentication")
	}
	
	// Test authentication with wrong passphrase
	wrongReq := &vault.AuthenticateRequest{
		DeviceId:   deviceID,
		Passphrase: "wrong-passphrase",
	}
	
	_, err = ts.client.Authenticate(context.Background(), wrongReq)
	if err == nil {
		t.Error("Expected authentication to fail with wrong passphrase")
	}
	
	// Check that it's an unauthenticated error
	if st, ok := status.FromError(err); ok {
		if st.Code() != codes.Unauthenticated {
			t.Errorf("Expected Unauthenticated error, got %v", st.Code())
		}
	}
}

func testSecretCRUD(t *testing.T, ts *TestServer, authCtx context.Context) {
	const secretName = "test-secret"
	const secretData = "my-secret-password"
	
	// Create secret
	createReq := &vault.CreateSecretRequest{
		Secret: &vault.Secret{
			Name: secretName,
			Metadata: &vault.SecretMetadata{
				Category: "password",
				Tags:     []string{"test", "integration"},
				CustomFields: map[string]string{
					"website": "example.com",
				},
			},
		},
		PlaintextData: []byte(secretData),
	}
	
	createResp, err := ts.client.CreateSecret(authCtx, createReq)
	if err != nil {
		t.Fatalf("Create secret failed: %v", err)
	}
	
	if createResp.Secret.Id == "" {
		t.Error("Expected non-empty secret ID")
	}
	
	if createResp.Secret.Name != secretName {
		t.Errorf("Expected secret name %s, got %s", secretName, createResp.Secret.Name)
	}
	
	secretID := createResp.Secret.Id
	
	// Get secret without data
	getReq := &vault.GetSecretRequest{
		Identifier:  secretName,
		IncludeData: false,
	}
	
	getResp, err := ts.client.GetSecret(authCtx, getReq)
	if err != nil {
		t.Fatalf("Get secret failed: %v", err)
	}
	
	if getResp.Secret.Name != secretName {
		t.Errorf("Expected secret name %s, got %s", secretName, getResp.Secret.Name)
	}
	
	if getResp.DecryptedData != nil {
		t.Error("Expected no decrypted data when IncludeData=false")
	}
	
	// Get secret with data
	getReq.IncludeData = true
	getResp, err = ts.client.GetSecret(authCtx, getReq)
	if err != nil {
		t.Fatalf("Get secret with data failed: %v", err)
	}
	
	if string(getResp.DecryptedData) != secretData {
		t.Errorf("Expected secret data %s, got %s", secretData, string(getResp.DecryptedData))
	}
	
	// Update secret
	newSecretData := "updated-secret-password"
	updateReq := &vault.UpdateSecretRequest{
		Secret: &vault.Secret{
			Id:   secretID,
			Name: secretName,
			Metadata: &vault.SecretMetadata{
				Category: "password",
				Tags:     []string{"test", "integration", "updated"},
				CustomFields: map[string]string{
					"website": "newexample.com",
				},
			},
		},
		PlaintextData: []byte(newSecretData),
	}
	
	updateResp, err := ts.client.UpdateSecret(authCtx, updateReq)
	if err != nil {
		t.Fatalf("Update secret failed: %v", err)
	}
	
	if updateResp.Secret.Version <= createResp.Secret.Version {
		t.Error("Expected secret version to increase after update")
	}
	
	// Verify update
	getResp, err = ts.client.GetSecret(authCtx, &vault.GetSecretRequest{
		Identifier:  secretName,
		IncludeData: true,
	})
	if err != nil {
		t.Fatalf("Get updated secret failed: %v", err)
	}
	
	if string(getResp.DecryptedData) != newSecretData {
		t.Errorf("Expected updated secret data %s, got %s", newSecretData, string(getResp.DecryptedData))
	}
	
	if len(getResp.Secret.Metadata.Tags) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(getResp.Secret.Metadata.Tags))
	}
	
	// Delete secret
	deleteReq := &vault.DeleteSecretRequest{
		Id: secretID,
	}
	
	_, err = ts.client.DeleteSecret(authCtx, deleteReq)
	if err != nil {
		t.Fatalf("Delete secret failed: %v", err)
	}
	
	// Verify deletion
	_, err = ts.client.GetSecret(authCtx, &vault.GetSecretRequest{
		Identifier: secretName,
	})
	if err == nil {
		t.Error("Expected error when getting deleted secret")
	}
	
	if st, ok := status.FromError(err); ok {
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound error, got %v", st.Code())
		}
	}
}

func testSecretListing(t *testing.T, ts *TestServer, authCtx context.Context) {
	// Create multiple secrets for testing
	secrets := []struct {
		name     string
		category string
		tags     []string
	}{
		{"secret1", "password", []string{"web", "important"}},
		{"secret2", "api-key", []string{"api", "service"}},
		{"secret3", "password", []string{"database", "important"}},
	}
	
	// Create secrets
	for _, s := range secrets {
		createReq := &vault.CreateSecretRequest{
			Secret: &vault.Secret{
				Name: s.name,
				Metadata: &vault.SecretMetadata{
					Category: s.category,
					Tags:     s.tags,
				},
			},
			PlaintextData: []byte("secret-data-" + s.name),
		}
		
		_, err := ts.client.CreateSecret(authCtx, createReq)
		if err != nil {
			t.Fatalf("Failed to create secret %s: %v", s.name, err)
		}
	}
	
	// List all secrets
	listReq := &vault.ListSecretsRequest{
		PageSize: 10,
	}
	
	listResp, err := ts.client.ListSecrets(authCtx, listReq)
	if err != nil {
		t.Fatalf("List secrets failed: %v", err)
	}
	
	if len(listResp.Secrets) != 3 {
		t.Errorf("Expected 3 secrets, got %d", len(listResp.Secrets))
	}
	
	// Test pagination
	listReq = &vault.ListSecretsRequest{
		PageSize: 2,
	}
	listResp, err = ts.client.ListSecrets(authCtx, listReq)
	if err != nil {
		t.Fatalf("List secrets with pagination failed: %v", err)
	}
	
	if len(listResp.Secrets) != 2 {
		t.Errorf("Expected 2 secrets in first page, got %d", len(listResp.Secrets))
	}
	
	if listResp.NextPageToken == "" {
		t.Error("Expected next page token")
	}
}

func testAuditLogging(t *testing.T, ts *TestServer, authCtx context.Context) {
	// Create a secret to generate audit logs
	createReq := &vault.CreateSecretRequest{
		Secret: &vault.Secret{
			Name: "audit-test-secret",
		},
		PlaintextData: []byte("audit-test-data"),
	}
	
	_, err := ts.client.CreateSecret(authCtx, createReq)
	if err != nil {
		t.Fatalf("Create secret for audit test failed: %v", err)
	}
	
	// Get audit logs
	auditReq := &vault.GetAuditLogRequest{
		PageSize: 10,
	}
	
	auditResp, err := ts.client.GetAuditLog(authCtx, auditReq)
	if err != nil {
		t.Fatalf("Get audit log failed: %v", err)
	}
	
	if len(auditResp.Entries) == 0 {
		t.Error("Expected audit log entries")
	}
	
	// Check for create_secret operation
	found := false
	for _, entry := range auditResp.Entries {
		if entry.Action == "create_secret" {
			found = true
			if entry.Result != "success" {
				t.Errorf("Expected successful audit entry, got %s", entry.Result)
			}
			break
		}
	}
	
	if !found {
		t.Error("Expected to find create_secret audit entry")
	}
}

func testErrorHandling(t *testing.T, ts *TestServer, authCtx context.Context) {
	// Test unauthenticated access
	_, err := ts.client.CreateSecret(context.Background(), &vault.CreateSecretRequest{
		Secret: &vault.Secret{Name: "test"},
	})
	if err == nil {
		t.Error("Expected error for unauthenticated request")
	}
	
	if st, ok := status.FromError(err); ok {
		if st.Code() != codes.Unauthenticated {
			t.Errorf("Expected Unauthenticated error, got %v", st.Code())
		}
	}
	
	// Test getting non-existent secret
	_, err = ts.client.GetSecret(authCtx, &vault.GetSecretRequest{
		Identifier: "non-existent-secret",
	})
	if err == nil {
		t.Error("Expected error for non-existent secret")
	}
	
	if st, ok := status.FromError(err); ok {
		if st.Code() != codes.NotFound {
			t.Errorf("Expected NotFound error, got %v", st.Code())
		}
	}
	
	// Test creating secret with empty name
	_, err = ts.client.CreateSecret(authCtx, &vault.CreateSecretRequest{
		Secret: &vault.Secret{Name: ""},
	})
	if err == nil {
		t.Error("Expected error for secret with empty name")
	}
	
	if st, ok := status.FromError(err); ok {
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Expected InvalidArgument error, got %v", st.Code())
		}
	}
}

func testTokenManagement(t *testing.T, ts *TestServer, deviceID, passphrase string) {
	// Authenticate to get initial token
	authReq := &vault.AuthenticateRequest{
		DeviceId:   deviceID,
		Passphrase: passphrase,
	}
	
	authResp, err := ts.client.Authenticate(context.Background(), authReq)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}
	
	originalToken := authResp.Token
	refreshToken := authResp.RefreshToken
	
	// Test token refresh
	refreshReq := &vault.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}
	
	refreshResp, err := ts.client.RefreshToken(context.Background(), refreshReq)
	if err != nil {
		t.Fatalf("Token refresh failed: %v", err)
	}
	
	if refreshResp.Token == "" {
		t.Error("Expected new token from refresh")
	}
	
	if refreshResp.Token == originalToken {
		t.Error("Expected different token after refresh")
	}
	
	// Test token revocation
	revokeReq := &vault.RevokeTokenRequest{
		Token: &refreshResp.Token,
	}
	
	_, err = ts.client.RevokeToken(context.Background(), revokeReq)
	if err != nil {
		t.Fatalf("Token revocation failed: %v", err)
	}
	
	// Verify revoked token doesn't work
	authCtx := createAuthenticatedContext(refreshResp.Token)
	_, err = ts.client.GetAuditLog(authCtx, &vault.GetAuditLogRequest{})
	if err == nil {
		t.Error("Expected error when using revoked token")
	}
}