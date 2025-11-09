package server

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
	"github.com/Neph-dev/nef-vault/pkg/crypto"
	"github.com/Neph-dev/nef-vault/pkg/store"
)

// Helper methods for VaultServiceServer

// logAuditEvent records an audit event for vault operations
func (v *VaultServiceServer) logAuditEvent(ctx context.Context, deviceID, operation, resource string, success bool, errorMsg string) {
	sessionID, _ := ctx.Value("session_id").(string)
	
	auditLog := &store.AuditLog{
		Operation:        operation,
		UserID:           deviceID,
		DeviceID:         deviceID,
		ClientIP:         stringPtr(getClientIP(ctx)),
		UserAgent:        stringPtr(getUserAgent(ctx)),
		OperationDetails: map[string]string{
			"resource": resource,
		},
		Success:   success,
		SessionID: stringPtr(sessionID),
		Timestamp: time.Now(),
	}

	if !success && errorMsg != "" {
		auditLog.ErrorMessage = &errorMsg
		auditLog.OperationDetails["error"] = errorMsg
	}

	if resource != "" {
		auditLog.SecretID = &resource
	}

	// Use the auth service to log the event
	v.authService.logAuditEvent(ctx, auditLog)
}

// encryptData encrypts data using AES-GCM with the provided master key
func (v *VaultServiceServer) encryptData(data, masterKey []byte) (*crypto.EncryptedSecret, error) {
	// Use the crypto package encryption function
	return crypto.EncryptSecret(masterKey, data)
}

// decryptData decrypts data using AES-GCM with the provided master key
func (v *VaultServiceServer) decryptData(encrypted *crypto.EncryptedSecret, masterKey []byte) ([]byte, error) {
	// Use the crypto package decryption function
	return crypto.DecryptSecret(masterKey, encrypted)
}

// Helper functions to serialize/deserialize EncryptedSecret

// serializeEncryptedSecret converts an EncryptedSecret to bytes for storage
func (v *VaultServiceServer) serializeEncryptedSecret(es *crypto.EncryptedSecret) []byte {
	// Simple serialization: version(4) + dataKeyLen(4) + dataKey + dataLen(4) + data
	result := make([]byte, 0, 4+4+len(es.EncryptedDataKey)+4+len(es.EncryptedData))
	
	// Version (4 bytes)
	versionBytes := make([]byte, 4)
	result = append(result, versionBytes...)
	result[0] = byte(es.Version >> 24)
	result[1] = byte(es.Version >> 16)
	result[2] = byte(es.Version >> 8)
	result[3] = byte(es.Version)
	
	// Data key length (4 bytes)
	dataKeyLen := len(es.EncryptedDataKey)
	result = append(result, byte(dataKeyLen>>24), byte(dataKeyLen>>16), byte(dataKeyLen>>8), byte(dataKeyLen))
	
	// Data key
	result = append(result, es.EncryptedDataKey...)
	
	// Data length (4 bytes)
	dataLen := len(es.EncryptedData)
	result = append(result, byte(dataLen>>24), byte(dataLen>>16), byte(dataLen>>8), byte(dataLen))
	
	// Data
	result = append(result, es.EncryptedData...)
	
	return result
}

// deserializeEncryptedSecret converts bytes back to EncryptedSecret
func (v *VaultServiceServer) deserializeEncryptedSecret(data []byte) (*crypto.EncryptedSecret, error) {
	if len(data) < 12 { // minimum: version(4) + dataKeyLen(4) + dataLen(4)
		return nil, fmt.Errorf("insufficient data length: %d", len(data))
	}
	
	// Extract version
	version := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	
	// Extract data key length
	dataKeyLen := int(data[4])<<24 | int(data[5])<<16 | int(data[6])<<8 | int(data[7])
	
	if len(data) < 12+dataKeyLen {
		return nil, fmt.Errorf("insufficient data for data key: expected %d, got %d", 12+dataKeyLen, len(data))
	}
	
	// Extract data key
	dataKey := make([]byte, dataKeyLen)
	copy(dataKey, data[8:8+dataKeyLen])
	
	// Extract data length
	dataLenOffset := 8 + dataKeyLen
	if len(data) < dataLenOffset+4 {
		return nil, fmt.Errorf("insufficient data for data length")
	}
	
	dataLen := int(data[dataLenOffset])<<24 | int(data[dataLenOffset+1])<<16 | int(data[dataLenOffset+2])<<8 | int(data[dataLenOffset+3])
	
	if len(data) < dataLenOffset+4+dataLen {
		return nil, fmt.Errorf("insufficient data for encrypted data: expected %d, got %d", dataLenOffset+4+dataLen, len(data))
	}
	
	// Extract encrypted data
	encryptedData := make([]byte, dataLen)
	copy(encryptedData, data[dataLenOffset+4:dataLenOffset+4+dataLen])
	
	return &crypto.EncryptedSecret{
		EncryptedDataKey: dataKey,
		EncryptedData:    encryptedData,
		Version:          version,
	}, nil
}

// convertStoreSecretToProto converts a store.Secret to vault.Secret
func (v *VaultServiceServer) convertStoreSecretToProto(s *store.Secret) *vault.Secret {
	protoSecret := &vault.Secret{
		Id:              s.ID,
		Name:            s.Name,
		EncryptedData:   s.EncryptedData,
		EncryptedDataKey: s.EncryptedKey,
		CreatedAt:       timestamppb.New(s.CreatedAt),
		UpdatedAt:       timestamppb.New(s.UpdatedAt),
		Version:         s.Version,
		EncryptionVersion: 1, // Current encryption version
	}

	// Set expiry date if present
	if s.ExpiryDate != nil {
		protoSecret.ExpiresAt = timestamppb.New(*s.ExpiryDate)
	}

	// Convert metadata
	if len(s.Metadata) > 0 || len(s.Tags) > 0 || s.Category != "" {
		protoSecret.Metadata = &vault.SecretMetadata{
			Category:     s.Category,
			Tags:         s.Tags,
			CustomFields: s.Metadata,
		}
	}

	// Convert scope
	protoSecret.Scope = &vault.SecretScope{
		Level: convertScopeToProto(s.Scope),
	}

	return protoSecret
}

// convertSecretMetaToProto converts a store.SecretMeta to vault.Secret
func (v *VaultServiceServer) convertSecretMetaToProto(meta *store.SecretMeta) *vault.Secret {
	protoSecret := &vault.Secret{
		Id:        meta.ID,
		Name:      meta.Name,
		CreatedAt: timestamppb.New(meta.CreatedAt),
		UpdatedAt: timestamppb.New(meta.UpdatedAt),
		Version:   meta.Version,
		EncryptionVersion: 1,
	}

	// Set expiry date if present
	if meta.ExpiryDate != nil {
		protoSecret.ExpiresAt = timestamppb.New(*meta.ExpiryDate)
	}

	// Convert metadata
	if len(meta.Metadata) > 0 || len(meta.Tags) > 0 || meta.Category != "" {
		protoSecret.Metadata = &vault.SecretMetadata{
			Category:     meta.Category,
			Tags:         meta.Tags,
			CustomFields: meta.Metadata,
		}
	}

	// Convert scope
	protoSecret.Scope = &vault.SecretScope{
		Level: convertScopeToProto(meta.Scope),
	}

	return protoSecret
}

// convertAuditLogToProto converts a store.AuditLog to vault.AuditEntry
func (v *VaultServiceServer) convertAuditLogToProto(log *store.AuditLog) *vault.AuditEntry {
	entry := &vault.AuditEntry{
		Id:        fmt.Sprintf("%d", log.ID),
		Timestamp: timestamppb.New(log.Timestamp),
		EventType: log.Operation,
		Actor:     log.UserID,
		Action:    log.Operation,
		Result:    getResultString(log.Success),
		Details:   log.OperationDetails,
	}

	// Set resource if available
	if log.SecretID != nil {
		entry.Resource = *log.SecretID
	}

	// Set IP address if available
	if log.ClientIP != nil {
		entry.IpAddress = *log.ClientIP
	}

	// Set user agent if available
	if log.UserAgent != nil {
		entry.UserAgent = *log.UserAgent
	}

	// Set session ID if available
	if log.SessionID != nil {
		entry.SessionId = *log.SessionID
	}

	return entry
}

// Helper functions for converting between proto and store types

func getScope(protoScope *vault.SecretScope) string {
	if protoScope == nil {
		return store.ScopeUser
	}

	switch protoScope.Level {
	case vault.ScopeLevel_SCOPE_LEVEL_PRIVATE:
		return store.ScopeUser
	case vault.ScopeLevel_SCOPE_LEVEL_ALL_DEVICES:
		return store.ScopeShared
	default:
		return store.ScopeUser
	}
}

func convertScopeToProto(scope string) vault.ScopeLevel {
	switch scope {
	case store.ScopeUser:
		return vault.ScopeLevel_SCOPE_LEVEL_PRIVATE
	case store.ScopeShared:
		return vault.ScopeLevel_SCOPE_LEVEL_ALL_DEVICES
	case store.ScopeSystem:
		return vault.ScopeLevel_SCOPE_LEVEL_ALL_DEVICES
	default:
		return vault.ScopeLevel_SCOPE_LEVEL_PRIVATE
	}
}

func getCategory(metadata *vault.SecretMetadata) string {
	if metadata == nil {
		return store.CategoryGeneral
	}
	
	if metadata.Category == "" {
		return store.CategoryGeneral
	}

	// Validate and convert category
	if store.IsValidCategory(metadata.Category) {
		return metadata.Category
	}

	return store.CategoryGeneral
}

func getTags(metadata *vault.SecretMetadata) []string {
	if metadata == nil {
		return nil
	}
	return metadata.Tags
}

func getExpiryDate(protoTime *timestamppb.Timestamp) *time.Time {
	if protoTime == nil {
		return nil
	}
	t := protoTime.AsTime()
	return &t
}

func getMetadataMap(metadata *vault.SecretMetadata) map[string]string {
	if metadata == nil {
		return nil
	}
	return metadata.CustomFields
}

func getFirstString(slice []string) string {
	if len(slice) == 0 {
		return ""
	}
	return slice[0]
}

func getResultString(success bool) string {
	if success {
		return "success"
	}
	return "failure"
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func parsePageToken(token string) (int, error) {
	return strconv.Atoi(token)
}

func generatePageToken(offset int) string {
	return strconv.Itoa(offset)
}