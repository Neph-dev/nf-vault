// Package auth provides authentication and authorization functionality for the vault.
// It implements JWT-like tokens with HMAC signing for secure authentication.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Neph-dev/nef-vault/pkg/crypto"
)

// ErrInvalidToken is returned when a token is malformed or invalid.
var ErrInvalidToken = errors.New("invalid token")

// ErrTokenExpired is returned when a token has expired.
var ErrTokenExpired = errors.New("token expired")

// ErrInvalidSignature is returned when a token signature verification fails.
var ErrInvalidSignature = errors.New("invalid token signature")

// TokenClaims represents the payload of an authentication token.
type TokenClaims struct {
	// UserID is the unique identifier of the authenticated user
	UserID string `json:"user_id"`
	
	// DeviceID is the unique identifier of the device/client
	DeviceID string `json:"device_id"`
	
	// ExpiresAt is the expiration time as Unix timestamp
	ExpiresAt int64 `json:"exp"`
	
	// IssuedAt is the time when token was issued as Unix timestamp
	IssuedAt int64 `json:"iat"`
	
	// Issuer identifies who issued the token
	Issuer string `json:"iss,omitempty"`
	
	// Subject identifies the principal that is the subject of the JWT
	Subject string `json:"sub,omitempty"`
	
	// Scope defines the access permissions for this token
	Scope string `json:"scope,omitempty"`
	
	// TokenID is a unique identifier for this specific token (for revocation)
	TokenID string `json:"jti,omitempty"`
}

// TokenManager handles token creation, validation, and management.
type TokenManager struct {
	// signingKey is the HMAC key used for token signing
	signingKey []byte
	
	// defaultTTL is the default time-to-live for tokens
	defaultTTL time.Duration
	
	// issuer is the default issuer for tokens
	issuer string
}

// NewTokenManager creates a new token manager with the specified signing key.
func NewTokenManager(signingKey []byte, defaultTTL time.Duration, issuer string) (*TokenManager, error) {
	if len(signingKey) < 32 {
		return nil, errors.New("signing key must be at least 32 bytes")
	}
	
	if defaultTTL <= 0 {
		return nil, errors.New("default TTL must be positive")
	}
	
	if issuer == "" {
		return nil, errors.New("issuer cannot be empty")
	}
	
	return &TokenManager{
		signingKey: signingKey,
		defaultTTL: defaultTTL,
		issuer:     issuer,
	}, nil
}

// GenerateSigningKey creates a cryptographically secure signing key.
func GenerateSigningKey() ([]byte, error) {
	return crypto.GenerateRandomBytes(64) // 512-bit key for HMAC-SHA256
}

// CreateToken generates a new authentication token with the specified claims.
func (tm *TokenManager) CreateToken(userID, deviceID string, customTTL ...time.Duration) (string, error) {
	if userID == "" {
		return "", errors.New("user ID cannot be empty")
	}
	
	if deviceID == "" {
		return "", errors.New("device ID cannot be empty")
	}
	
	// Determine TTL
	ttl := tm.defaultTTL
	if len(customTTL) > 0 && customTTL[0] > 0 {
		ttl = customTTL[0]
	}
	
	// Generate unique token ID
	tokenID, err := crypto.GenerateSecureToken(32, crypto.TokenFormatBase64URL)
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}
	
	now := time.Now()
	claims := TokenClaims{
		UserID:    userID,
		DeviceID:  deviceID,
		ExpiresAt: now.Add(ttl).Unix(),
		IssuedAt:  now.Unix(),
		Issuer:    tm.issuer,
		Subject:   userID,
		Scope:     "vault:full", // Default full access scope
		TokenID:   tokenID,
	}
	
	return tm.signToken(claims)
}

// ValidateToken verifies a token's signature and checks its expiration.
func (tm *TokenManager) ValidateToken(token string) (*TokenClaims, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}
	
	// Parse token parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	
	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidToken
	}
	
	// Verify algorithm
	if alg, ok := header["alg"].(string); !ok || alg != "HS256" {
		return nil, ErrInvalidToken
	}
	
	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	
	var claims TokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	
	// Verify signature
	expectedToken, err := tm.signToken(claims)
	if err != nil {
		return nil, ErrInvalidSignature
	}
	
	if !hmac.Equal([]byte(token), []byte(expectedToken)) {
		return nil, ErrInvalidSignature
	}
	
	// Check expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}
	
	return &claims, nil
}

// RefreshToken creates a new token with extended expiration based on an existing valid token.
func (tm *TokenManager) RefreshToken(oldToken string, newTTL ...time.Duration) (string, error) {
	claims, err := tm.ValidateToken(oldToken)
	if err != nil {
		return "", fmt.Errorf("cannot refresh invalid token: %w", err)
	}
	
	// Create new token with same user/device but new expiration
	ttl := tm.defaultTTL
	if len(newTTL) > 0 && newTTL[0] > 0 {
		ttl = newTTL[0]
	}
	
	return tm.CreateToken(claims.UserID, claims.DeviceID, ttl)
}

// ExtractClaims extracts claims from a token without validating the signature.
// This should only be used for informational purposes, not for authentication.
func (tm *TokenManager) ExtractClaims(token string) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	
	var claims TokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	
	return &claims, nil
}

// signToken creates a signed JWT-like token from the given claims.
func (tm *TokenManager) signToken(claims TokenClaims) (string, error) {
	// Create header
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	
	// Create payload
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	
	// Encode header and payload
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)
	
	// Create signature
	message := headerEncoded + "." + payloadEncoded
	mac := hmac.New(sha256.New, tm.signingKey)
	mac.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	
	return message + "." + signature, nil
}

// IsExpired checks if a token is expired based on its claims.
func (claims *TokenClaims) IsExpired() bool {
	return time.Now().Unix() > claims.ExpiresAt
}

// TimeUntilExpiry returns the duration until the token expires.
func (claims *TokenClaims) TimeUntilExpiry() time.Duration {
	return time.Until(time.Unix(claims.ExpiresAt, 0))
}

// String returns a string representation of the claims for debugging.
func (claims *TokenClaims) String() string {
	return fmt.Sprintf("TokenClaims{UserID:%s, DeviceID:%s, ExpiresAt:%s, IssuedAt:%s, TokenID:%s}",
		claims.UserID,
		claims.DeviceID,
		time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339),
		time.Unix(claims.IssuedAt, 0).Format(time.RFC3339),
		claims.TokenID,
	)
}

// Validate performs basic validation on token claims.
func (claims *TokenClaims) Validate() error {
	if claims.UserID == "" {
		return errors.New("user ID cannot be empty")
	}
	
	if claims.DeviceID == "" {
		return errors.New("device ID cannot be empty")
	}
	
	if claims.ExpiresAt <= 0 {
		return errors.New("expiration time must be positive")
	}
	
	if claims.IssuedAt <= 0 {
		return errors.New("issued at time must be positive")
	}
	
	if claims.ExpiresAt <= claims.IssuedAt {
		return errors.New("expiration time must be after issued time")
	}
	
	return nil
}

// HasScope checks if the token has the specified scope.
func (claims *TokenClaims) HasScope(scope string) bool {
	if claims.Scope == "" {
		return false
	}
	
	// Simple scope matching - can be extended for complex scope logic
	scopes := strings.Split(claims.Scope, " ")
	for _, s := range scopes {
		if s == scope || s == "vault:full" {
			return true
		}
	}
	
	return false
}

// TokenRevocationList manages revoked tokens.
type TokenRevocationList struct {
	revokedTokens map[string]time.Time // tokenID -> revocation time
}

// NewTokenRevocationList creates a new token revocation list.
func NewTokenRevocationList() *TokenRevocationList {
	return &TokenRevocationList{
		revokedTokens: make(map[string]time.Time),
	}
}

// RevokeToken adds a token to the revocation list.
func (trl *TokenRevocationList) RevokeToken(tokenID string) {
	trl.revokedTokens[tokenID] = time.Now()
}

// IsRevoked checks if a token is revoked.
func (trl *TokenRevocationList) IsRevoked(tokenID string) bool {
	_, exists := trl.revokedTokens[tokenID]
	return exists
}

// CleanupExpired removes revoked tokens that have already expired.
func (trl *TokenRevocationList) CleanupExpired() {
	cutoff := time.Now().Add(-24 * time.Hour) // Remove tokens revoked more than 24h ago
	
	for tokenID, revokedAt := range trl.revokedTokens {
		if revokedAt.Before(cutoff) {
			delete(trl.revokedTokens, tokenID)
		}
	}
}

// Size returns the number of revoked tokens.
func (trl *TokenRevocationList) Size() int {
	return len(trl.revokedTokens)
}