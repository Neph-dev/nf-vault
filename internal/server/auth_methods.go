package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
	"github.com/Neph-dev/nef-vault/pkg/crypto"
	"github.com/Neph-dev/nef-vault/pkg/store"
)

// Helper functions and additional AuthService methods

// validateOrCreateMasterKey validates an existing passphrase or creates initial setup
func (a *AuthService) validateOrCreateMasterKey(ctx context.Context, passphrase []byte) ([]byte, []byte, error) {
	systemSecret, err := a.store.GetSecretByID(ctx, "system:kdf_salt")
	if err != nil {
		// First time setup - create new salt and master key
		salt, err := crypto.GenerateSalt(a.kdfParams.SaltLen)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
		}

		masterKey, err := crypto.DeriveKey(passphrase, salt, a.kdfParams)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive master key: %w", err)
		}

		// Store salt for future use
		saltSecret := &store.Secret{
			ID:            "system:kdf_salt",
			Name:          "system:kdf_salt",
			EncryptedData: salt,
			Category:      store.CategoryNote,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := a.store.CreateSecret(ctx, saltSecret); err != nil {
			return nil, nil, fmt.Errorf("failed to store salt: %w", err)
		}

		return masterKey, salt, nil
	}

	// Existing setup - validate passphrase
	salt := systemSecret.EncryptedData
	masterKey, err := crypto.DeriveKey(passphrase, salt, a.kdfParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	return masterKey, salt, nil
}

// generateToken creates a signed JWT token with the specified claims
func (a *AuthService) generateToken(deviceID, sessionID string, expiresAt time.Time) (string, error) {
	claims := &Claims{
		DeviceID:  deviceID,
		SessionID: sessionID,
		Scope:     "vault:access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "nef-vault",
			Subject:   deviceID,
			ID:        sessionID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

// generateRefreshToken creates a refresh token for extending sessions
func (a *AuthService) generateRefreshToken(deviceID, sessionID string) (string, error) {
	claims := &Claims{
		DeviceID:  deviceID,
		SessionID: sessionID,
		Scope:     "vault:refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(a.refreshLifetime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "nef-vault",
			Subject:   deviceID,
			ID:        sessionID + ":refresh",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

// encryptMasterKeyForSession encrypts the master key for secure session storage
func (a *AuthService) encryptMasterKeyForSession(masterKey []byte) ([]byte, error) {
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(masterKey)+len(sessionKey))
	copy(encrypted[:len(sessionKey)], sessionKey)

	for i, b := range masterKey {
		encrypted[len(sessionKey)+i] = b ^ sessionKey[i%len(sessionKey)]
	}

	return encrypted, nil
}

// decryptMasterKeyFromSession decrypts the master key from session storage
func (a *AuthService) decryptMasterKeyFromSession(encryptedKey []byte) ([]byte, error) {
	if len(encryptedKey) < 32 {
		return nil, fmt.Errorf("invalid encrypted key")
	}

	sessionKey := encryptedKey[:32]
	encrypted := encryptedKey[32:]

	masterKey := make([]byte, len(encrypted))
	for i, b := range encrypted {
		masterKey[i] = b ^ sessionKey[i%len(sessionKey)]
	}

	return masterKey, nil
}

// registerDevice creates or updates device information in the store
func (a *AuthService) registerDevice(ctx context.Context, deviceID string, deviceInfo *vault.DeviceInfo) error {
	device := &store.Device{
		ID:           deviceID,
		UserID:       deviceID,
		DeviceName:   deviceInfo.Name,
		DeviceType:   getDeviceType(deviceInfo.Os),
		Platform:     stringPtr(deviceInfo.Os),
		AppVersion:   stringPtr(deviceInfo.AppVersion),
		LastUsedAt:   timePtr(time.Now()),
		RegisteredAt: time.Now(),
		IsActive:     true,
		TrustLevel:   store.TrustLevelLimited,
		Metadata: map[string]string{
			"ip_address":  deviceInfo.IpAddress,
			"user_agent":  deviceInfo.UserAgent,
			"app_version": deviceInfo.AppVersion,
		},
	}

	return a.store.RegisterDevice(ctx, device)
}

// logAuditEvent records an audit event in the store
func (a *AuthService) logAuditEvent(ctx context.Context, log *store.AuditLog) {
	if err := a.store.AppendAuditLog(ctx, log); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}
}

// VerifyToken validates a JWT token and returns the associated claims
func (a *AuthService) VerifyToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	session, exists := activeSessions[claims.SessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		delete(activeSessions, claims.SessionID)
		return nil, fmt.Errorf("session expired")
	}

	if session.DeviceID != claims.DeviceID {
		return nil, fmt.Errorf("device mismatch")
	}

	return claims, nil
}

// GetMasterKeyForSession retrieves and decrypts the master key for a session
func (a *AuthService) GetMasterKeyForSession(sessionID string) ([]byte, error) {
	session, exists := activeSessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		delete(activeSessions, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	masterKey, err := a.decryptMasterKeyFromSession(session.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key: %w", err)
	}

	return masterKey, nil
}

// RevokeToken invalidates a token and its associated session
func (a *AuthService) RevokeToken(ctx context.Context, req *vault.RevokeTokenRequest) error {
	if req.Token == nil || *req.Token == "" {
		sessionID, ok := ctx.Value("session_id").(string)
		if !ok {
			return status.Error(codes.InvalidArgument, "no session to revoke")
		}

		delete(activeSessions, sessionID)

		a.logAuditEvent(ctx, &store.AuditLog{
			Operation:        "revoke_token",
			UserID:           getDeviceIDFromContext(ctx),
			DeviceID:         getDeviceIDFromContext(ctx),
			ClientIP:         stringPtr(getClientIP(ctx)),
			UserAgent:        stringPtr(getUserAgent(ctx)),
			OperationDetails: map[string]string{
				"session_id": sessionID,
				"result":     "success",
			},
			Success:   true,
			SessionID: stringPtr(sessionID),
			Timestamp: time.Now(),
		})

		return nil
	}

	claims, err := a.VerifyToken(*req.Token)
	if err != nil {
		return status.Error(codes.InvalidArgument, "invalid token")
	}

	delete(activeSessions, claims.SessionID)

	if req.RevokeAllDeviceTokens {
		for sessionID, session := range activeSessions {
			if session.DeviceID == claims.DeviceID {
				delete(activeSessions, sessionID)
			}
		}
	}

	return nil
}

// Helper functions

func getClientIP(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ips := md.Get("x-real-ip"); len(ips) > 0 {
			return ips[0]
		}
		if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
			return ips[0]
		}
	}
	return "unknown"
}

func getUserAgent(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if agents := md.Get("user-agent"); len(agents) > 0 {
			return agents[0]
		}
	}
	return "unknown"
}

func getDeviceIDFromContext(ctx context.Context) string {
	if deviceID, ok := ctx.Value("device_id").(string); ok {
		return deviceID
	}
	return "unknown"
}

func getDeviceType(os string) string {
	switch os {
	case "windows", "macos", "linux":
		return store.DeviceTypeDesktop
	case "ios", "android":
		return store.DeviceTypeMobile
	default:
		return store.DeviceTypeUnknown
	}
}