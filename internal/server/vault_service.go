package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
	"github.com/Neph-dev/nef-vault/pkg/crypto"
	"github.com/Neph-dev/nef-vault/pkg/store"
)

// VaultServiceServer implements the VaultService gRPC interface
type VaultServiceServer struct {
	vault.UnimplementedVaultServiceServer
	store       store.Store
	authService *AuthService
}

// NewVaultServiceServer creates a new VaultService server
func NewVaultServiceServer(store store.Store, authService *AuthService) *VaultServiceServer {
	return &VaultServiceServer{
		store:       store,
		authService: authService,
	}
}

// Authenticate handles device authentication and returns JWT tokens
func (v *VaultServiceServer) Authenticate(ctx context.Context, req *vault.AuthenticateRequest) (*vault.AuthenticateResponse, error) {
	if req.DeviceId == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required")
	}
	
	if req.Passphrase == "" {
		return nil, status.Error(codes.InvalidArgument, "passphrase is required")
	}
	
	// Use the auth service to authenticate - it expects the same proto types
	return v.authService.Authenticate(ctx, req)
}

// RefreshToken creates a new access token using a refresh token
func (v *VaultServiceServer) RefreshToken(ctx context.Context, req *vault.RefreshTokenRequest) (*vault.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}
	
	// Verify the refresh token
	claims, err := v.authService.VerifyToken(req.RefreshToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}
	
	// Check if it's actually a refresh token (scope should be vault:refresh)
	if claims.Scope != "vault:refresh" {
		return nil, status.Error(codes.InvalidArgument, "token is not a refresh token")
	}
	
	// Generate new access token (use 1 hour as default)
	expiresAt := time.Now().Add(time.Hour)
	newToken, err := v.authService.generateToken(claims.DeviceID, claims.SessionID, expiresAt)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate new token")
	}
	
	// Generate new refresh token
	newRefreshToken, err := v.authService.generateRefreshToken(claims.DeviceID, claims.SessionID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate new refresh token")
	}
	
	return &vault.RefreshTokenResponse{
		Token:        newToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    timestamppb.New(expiresAt),
	}, nil
}

// RevokeToken invalidates a token and its associated session
func (v *VaultServiceServer) RevokeToken(ctx context.Context, req *vault.RevokeTokenRequest) (*emptypb.Empty, error) {
	if req.Token == nil || *req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	
	// Use the auth service to revoke the token
	if err := v.authService.RevokeToken(ctx, req); err != nil {
		return nil, err // Error is already a gRPC status error from auth service
	}
	
	return &emptypb.Empty{}, nil
}

// CreateSecret stores a new secret in the vault with proper encryption
func (v *VaultServiceServer) CreateSecret(ctx context.Context, req *vault.CreateSecretRequest) (*vault.CreateSecretResponse, error) {
	// Get session information
	sessionID, ok := ctx.Value("session_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no session found")
	}

	deviceID, ok := ctx.Value("device_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no device found")
	}

	// Get master key for encryption
	masterKey, err := v.authService.GetMasterKeyForSession(sessionID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	defer crypto.SecureZero(masterKey)

	// Validate request
	if req.Secret == nil {
		return nil, status.Error(codes.InvalidArgument, "secret is required")
	}

	secretReq := req.Secret
	if secretReq.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "secret name is required")
	}

	// Check if secret already exists (unless overwrite is true)
	exists, err := v.store.SecretExists(ctx, secretReq.Name)
	if err != nil {
		v.logAuditEvent(ctx, deviceID, "create_secret", secretReq.Name, false, err.Error())
		return nil, status.Error(codes.Internal, "failed to check secret existence")
	}

	if exists && !req.Overwrite {
		v.logAuditEvent(ctx, deviceID, "create_secret", secretReq.Name, false, "secret already exists")
		return nil, status.Error(codes.AlreadyExists, "secret already exists")
	}

	// Generate secret ID if not provided
	secretID := secretReq.Id
	if secretID == "" {
		secretID = uuid.New().String()
	}

	// Generate per-secret encryption key
	secretKey := make([]byte, 32) // AES-256 key
	if _, err := rand.Read(secretKey); err != nil {
		v.logAuditEvent(ctx, deviceID, "create_secret", secretReq.Name, false, "failed to generate secret key")
		return nil, status.Error(codes.Internal, "failed to generate encryption key")
	}
	defer crypto.SecureZero(secretKey)

	// Extract plaintext data from the request
	var secretData []byte
	if req.PlaintextData != nil {
		secretData = req.PlaintextData
	}
	if len(secretData) == 0 && secretReq.EncryptedData != nil {
		// Client provided pre-encrypted data
		secretData = secretReq.EncryptedData
	}

	encryptedData, err := v.encryptData(secretData, secretKey)
	if err != nil {
		v.logAuditEvent(ctx, deviceID, "create_secret", secretReq.Name, false, "failed to encrypt data")
		return nil, status.Error(codes.Internal, "failed to encrypt secret data")
	}

	// Encrypt the per-secret key with the master key (KEK pattern)
	encryptedKey, err := v.encryptData(secretKey, masterKey)
	if err != nil {
		v.logAuditEvent(ctx, deviceID, "create_secret", secretReq.Name, false, "failed to encrypt key")
		return nil, status.Error(codes.Internal, "failed to encrypt secret key")
	}

	// Create store secret
	now := time.Now()
	storeSecret := &store.Secret{
		ID:            secretID,
		Name:          secretReq.Name,
		EncryptedKey:  v.serializeEncryptedSecret(encryptedKey),
		EncryptedData: v.serializeEncryptedSecret(encryptedData),
		Scope:         getScope(secretReq.Scope),
		Category:      getCategory(secretReq.Metadata),
		Tags:          getTags(secretReq.Metadata),
		ExpiryDate:    getExpiryDate(secretReq.ExpiresAt),
		CreatedAt:     now,
		UpdatedAt:     now,
		Version:       1,
		Metadata:      getMetadataMap(secretReq.Metadata),
	}

	// Store the secret
	if exists {
		err = v.store.UpdateSecret(ctx, storeSecret)
	} else {
		err = v.store.CreateSecret(ctx, storeSecret)
	}

	if err != nil {
		v.logAuditEvent(ctx, deviceID, "create_secret", secretReq.Name, false, err.Error())
		return nil, status.Error(codes.Internal, "failed to store secret")
	}

	// Log successful creation
	v.logAuditEvent(ctx, deviceID, "create_secret", secretReq.Name, true, "")

	// Return response
	return &vault.CreateSecretResponse{
		Secret: v.convertStoreSecretToProto(storeSecret),
	}, nil
}

// GetSecret retrieves a specific secret by name or ID with decryption
func (v *VaultServiceServer) GetSecret(ctx context.Context, req *vault.GetSecretRequest) (*vault.GetSecretResponse, error) {
	// Get session information
	sessionID, ok := ctx.Value("session_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no session found")
	}

	deviceID, ok := ctx.Value("device_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no device found")
	}

	// Validate request
	if req.Identifier == "" {
		return nil, status.Error(codes.InvalidArgument, "identifier is required")
	}

	// Try to get secret by name first, then by ID
	var storeSecret *store.Secret
	var err error

	storeSecret, err = v.store.GetSecret(ctx, req.Identifier)
	if err != nil {
		// Try by ID if name lookup failed
		storeSecret, err = v.store.GetSecretByID(ctx, req.Identifier)
		if err != nil {
			v.logAuditEvent(ctx, deviceID, "get_secret", req.Identifier, false, "secret not found")
			return nil, status.Error(codes.NotFound, "secret not found")
		}
	}

	// Convert to proto format
	protoSecret := v.convertStoreSecretToProto(storeSecret)
	response := &vault.GetSecretResponse{
		Secret: protoSecret,
	}

	// If decrypted data is requested, decrypt it
	if req.IncludeData {
		// Get master key for decryption
		masterKey, err := v.authService.GetMasterKeyForSession(sessionID)
		if err != nil {
			v.logAuditEvent(ctx, deviceID, "get_secret", req.Identifier, false, "invalid session")
			return nil, status.Error(codes.Unauthenticated, "invalid session")
		}
		defer crypto.SecureZero(masterKey)

		// Decrypt the per-secret key using master key
		encryptedKeySecret, err := v.deserializeEncryptedSecret(storeSecret.EncryptedKey)
		if err != nil {
			v.logAuditEvent(ctx, deviceID, "get_secret", req.Identifier, false, "failed to deserialize key")
			return nil, status.Error(codes.Internal, "failed to deserialize encrypted key")
		}
		
		secretKey, err := v.decryptData(encryptedKeySecret, masterKey)
		if err != nil {
			v.logAuditEvent(ctx, deviceID, "get_secret", req.Identifier, false, "failed to decrypt key")
			return nil, status.Error(codes.Internal, "failed to decrypt secret key")
		}
		defer crypto.SecureZero(secretKey)

		// Decrypt the secret data using per-secret key
		encryptedDataSecret, err := v.deserializeEncryptedSecret(storeSecret.EncryptedData)
		if err != nil {
			v.logAuditEvent(ctx, deviceID, "get_secret", req.Identifier, false, "failed to deserialize data")
			return nil, status.Error(codes.Internal, "failed to deserialize encrypted data")
		}
		
		decryptedData, err := v.decryptData(encryptedDataSecret, secretKey)
		if err != nil {
			v.logAuditEvent(ctx, deviceID, "get_secret", req.Identifier, false, "failed to decrypt data")
			return nil, status.Error(codes.Internal, "failed to decrypt secret data")
		}

		response.DecryptedData = decryptedData
	}

	// Log audit event if requested
	if req.AuditAccess {
		v.logAuditEvent(ctx, deviceID, "get_secret", req.Identifier, true, "")
	}

	return response, nil
}

// UpdateSecret modifies an existing secret
func (v *VaultServiceServer) UpdateSecret(ctx context.Context, req *vault.UpdateSecretRequest) (*vault.UpdateSecretResponse, error) {
	// Get session information
	sessionID, ok := ctx.Value("session_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no session found")
	}

	deviceID, ok := ctx.Value("device_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no device found")
	}

	// Validate request
	if req.Secret == nil || req.Secret.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "secret ID is required")
	}

	// Get existing secret for version check
	existingSecret, err := v.store.GetSecretByID(ctx, req.Secret.Id)
	if err != nil {
		v.logAuditEvent(ctx, deviceID, "update_secret", req.Secret.Id, false, "secret not found")
		return nil, status.Error(codes.NotFound, "secret not found")
	}

	// Check version for optimistic locking
	if req.ExpectedVersion > 0 && existingSecret.Version != req.ExpectedVersion {
		v.logAuditEvent(ctx, deviceID, "update_secret", req.Secret.Id, false, "version mismatch")
		return nil, status.Error(codes.FailedPrecondition, "version mismatch")
	}

	// Get master key for encryption/decryption
	masterKey, err := v.authService.GetMasterKeyForSession(sessionID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	defer crypto.SecureZero(masterKey)

	// Update the secret (similar to create but with version increment)
	updatedSecret := *existingSecret
	updatedSecret.UpdatedAt = time.Now()
	updatedSecret.Version++

	// Update fields based on update mask or update all if mask is empty
	if len(req.UpdateMask) == 0 || contains(req.UpdateMask, "name") {
		updatedSecret.Name = req.Secret.Name
	}
	if len(req.UpdateMask) == 0 || contains(req.UpdateMask, "metadata") {
		updatedSecret.Category = getCategory(req.Secret.Metadata)
		updatedSecret.Tags = getTags(req.Secret.Metadata)
		updatedSecret.Metadata = getMetadataMap(req.Secret.Metadata)
	}
	if len(req.UpdateMask) == 0 || contains(req.UpdateMask, "expires_at") {
		updatedSecret.ExpiryDate = getExpiryDate(req.Secret.ExpiresAt)
	}

	// If encrypted data is being updated, re-encrypt with new key
	if len(req.UpdateMask) == 0 || contains(req.UpdateMask, "encrypted_data") {
		// Generate new per-secret key
		newSecretKey := make([]byte, 32)
		if _, err := rand.Read(newSecretKey); err != nil {
			v.logAuditEvent(ctx, deviceID, "update_secret", req.Secret.Id, false, "failed to generate key")
			return nil, status.Error(codes.Internal, "failed to generate encryption key")
		}
		defer crypto.SecureZero(newSecretKey)

		// Encrypt new data
		var secretData []byte
		if req.PlaintextData != nil {
			secretData = req.PlaintextData
		}
		if len(secretData) == 0 && req.Secret.EncryptedData != nil {
			// Client provided pre-encrypted data
			secretData = req.Secret.EncryptedData
		}

		encryptedData, err := v.encryptData(secretData, newSecretKey)
		if err != nil {
			v.logAuditEvent(ctx, deviceID, "update_secret", req.Secret.Id, false, "failed to encrypt data")
			return nil, status.Error(codes.Internal, "failed to encrypt secret data")
		}

		// Encrypt new key with master key
		encryptedKey, err := v.encryptData(newSecretKey, masterKey)
		if err != nil {
			v.logAuditEvent(ctx, deviceID, "update_secret", req.Secret.Id, false, "failed to encrypt key")
			return nil, status.Error(codes.Internal, "failed to encrypt secret key")
		}

		updatedSecret.EncryptedData = v.serializeEncryptedSecret(encryptedData)
		updatedSecret.EncryptedKey = v.serializeEncryptedSecret(encryptedKey)
	}

	// Store the updated secret
	if err := v.store.UpdateSecret(ctx, &updatedSecret); err != nil {
		v.logAuditEvent(ctx, deviceID, "update_secret", req.Secret.Id, false, err.Error())
		return nil, status.Error(codes.Internal, "failed to update secret")
	}

	// Log successful update
	v.logAuditEvent(ctx, deviceID, "update_secret", req.Secret.Id, true, "")

	return &vault.UpdateSecretResponse{
		Secret: v.convertStoreSecretToProto(&updatedSecret),
	}, nil
}

// DeleteSecret removes a secret from the vault
func (v *VaultServiceServer) DeleteSecret(ctx context.Context, req *vault.DeleteSecretRequest) (*emptypb.Empty, error) {
	// Get session information
	deviceID, ok := ctx.Value("device_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no device found")
	}

	// Validate request
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "secret ID is required")
	}

	// Get existing secret for validation
	existingSecret, err := v.store.GetSecretByID(ctx, req.Id)
	if err != nil {
		v.logAuditEvent(ctx, deviceID, "delete_secret", req.Id, false, "secret not found")
		return nil, status.Error(codes.NotFound, "secret not found")
	}

	// Check version for optimistic locking
	if req.ExpectedVersion != nil && existingSecret.Version != *req.ExpectedVersion {
		v.logAuditEvent(ctx, deviceID, "delete_secret", req.Id, false, "version mismatch")
		return nil, status.Error(codes.FailedPrecondition, "version mismatch")
	}

	// Check if confirmation is required for important secrets
	if existingSecret.Category == store.CategoryCertificate || 
	   existingSecret.Category == store.CategorySSHKey {
		if !req.ConfirmDeletion {
			v.logAuditEvent(ctx, deviceID, "delete_secret", req.Id, false, "confirmation required")
			return nil, status.Error(codes.FailedPrecondition, "deletion confirmation required for important secrets")
		}
	}

	// Delete the secret
	if err := v.store.DeleteSecret(ctx, existingSecret.Name); err != nil {
		v.logAuditEvent(ctx, deviceID, "delete_secret", req.Id, false, err.Error())
		return nil, status.Error(codes.Internal, "failed to delete secret")
	}

	// Log successful deletion
	v.logAuditEvent(ctx, deviceID, "delete_secret", req.Id, true, "")

	return &emptypb.Empty{}, nil
}

// ListSecrets returns metadata for secrets matching criteria
func (v *VaultServiceServer) ListSecrets(ctx context.Context, req *vault.ListSecretsRequest) (*vault.ListSecretsResponse, error) {
	// Get session information
	deviceID, ok := ctx.Value("device_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no device found")
	}

	// Convert proto filter to store filter
	filter := &store.SecretFilter{
		Limit:  int(req.PageSize),
		Offset: 0, // We'll calculate this from page token
	}

	if req.Filter != nil {
		filter.Category = getFirstString(req.Filter.Categories)
		filter.Tags = req.Filter.Tags
		if req.Filter.CreatedRange != nil {
			if req.Filter.CreatedRange.Start != nil {
				start := req.Filter.CreatedRange.Start.AsTime()
				filter.CreatedAfter = &start
			}
			if req.Filter.CreatedRange.End != nil {
				end := req.Filter.CreatedRange.End.AsTime()
				filter.CreatedBefore = &end
			}
		}
	}

	// Handle pagination
	if req.PageToken != "" {
		// In a real implementation, you'd decode the page token
		// For simplicity, we'll assume it's a numeric offset
		if offset, err := parsePageToken(req.PageToken); err == nil {
			filter.Offset = offset
		}
	}

	// Get secrets from store
	secretMetas, err := v.store.ListSecrets(ctx, filter)
	if err != nil {
		v.logAuditEvent(ctx, deviceID, "list_secrets", "", false, err.Error())
		return nil, status.Error(codes.Internal, "failed to list secrets")
	}

	// Convert to proto format
	var protoSecrets []*vault.Secret
	for _, meta := range secretMetas {
		protoSecret := v.convertSecretMetaToProto(meta)
		protoSecrets = append(protoSecrets, protoSecret)
	}

	// Generate next page token if there are more results
	var nextPageToken string
	if len(secretMetas) == filter.Limit {
		nextPageToken = generatePageToken(filter.Offset + filter.Limit)
	}

	// Log successful listing
	v.logAuditEvent(ctx, deviceID, "list_secrets", "", true, fmt.Sprintf("returned %d secrets", len(protoSecrets)))

	return &vault.ListSecretsResponse{
		Secrets:       protoSecrets,
		NextPageToken: nextPageToken,
	}, nil
}

// GetAuditLog retrieves audit entries for security monitoring
func (v *VaultServiceServer) GetAuditLog(ctx context.Context, req *vault.GetAuditLogRequest) (*vault.GetAuditLogResponse, error) {
	// Get session information
	deviceID, ok := ctx.Value("device_id").(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no device found")
	}

	// Convert proto filter to store filter
	filter := &store.AuditFilter{
		Limit:  int(req.PageSize),
		Offset: 0,
	}

	if req.DeviceId != nil {
		filter.DeviceID = req.DeviceId
	}
	if req.UserId != nil {
		filter.UserID = req.UserId
	}
	if len(req.EventTypes) > 0 {
		operation := req.EventTypes[0] // Take first event type for simplicity
		filter.Operation = &operation
	}
	if req.TimeRange != nil {
		if req.TimeRange.Start != nil {
			start := req.TimeRange.Start.AsTime()
			filter.Since = &start
		}
		if req.TimeRange.End != nil {
			end := req.TimeRange.End.AsTime()
			filter.Until = &end
		}
	}

	// Handle pagination
	if req.PageToken != "" {
		if offset, err := parsePageToken(req.PageToken); err == nil {
			filter.Offset = offset
		}
	}

	// Get audit logs from store
	auditLogs, err := v.store.GetAuditLogs(ctx, filter)
	if err != nil {
		v.logAuditEvent(ctx, deviceID, "get_audit_log", "", false, err.Error())
		return nil, status.Error(codes.Internal, "failed to get audit logs")
	}

	// Convert to proto format
	var protoEntries []*vault.AuditEntry
	for _, log := range auditLogs {
		protoEntry := v.convertAuditLogToProto(log)
		protoEntries = append(protoEntries, protoEntry)
	}

	// Generate next page token
	var nextPageToken string
	if len(auditLogs) == filter.Limit {
		nextPageToken = generatePageToken(filter.Offset + filter.Limit)
	}

	// Log successful audit log retrieval
	v.logAuditEvent(ctx, deviceID, "get_audit_log", "", true, fmt.Sprintf("returned %d entries", len(protoEntries)))

	return &vault.GetAuditLogResponse{
		Entries:       protoEntries,
		NextPageToken: nextPageToken,
		TotalCount:    int64(len(protoEntries)), // In real implementation, this would be the total count
	}, nil
}

// Helper methods will be added in the next part...