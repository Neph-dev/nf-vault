package server

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
	"github.com/Neph-dev/nef-vault/pkg/crypto"
	"github.com/Neph-dev/nef-vault/pkg/store"
)

// AuthService handles authentication operations
type AuthService struct {
	store           store.Store
	jwtSecret       []byte
	masterKey       []byte
	kdfParams       crypto.KDFParams
	tokenLifetime   time.Duration
	refreshLifetime time.Duration
}

// AuthServiceConfig contains configuration for the authentication service
type AuthServiceConfig struct {
	Store           store.Store
	JWTSecret       []byte
	KDFParams       crypto.KDFParams
	TokenLifetime   time.Duration
	RefreshLifetime time.Duration
}

// NewAuthService creates a new authentication service
func NewAuthService(config AuthServiceConfig) *AuthService {
	return &AuthService{
		store:           config.Store,
		jwtSecret:       config.JWTSecret,
		kdfParams:       config.KDFParams,
		tokenLifetime:   config.TokenLifetime,
		refreshLifetime: config.RefreshLifetime,
	}
}

// Claims represents JWT token claims
type Claims struct {
	DeviceID  string `json:"device_id"`
	SessionID string `json:"session_id"`
	Scope     string `json:"scope"`
	jwt.RegisteredClaims
}

// SessionInfo contains session information
type SessionInfo struct {
	SessionID string
	DeviceID  string
	ExpiresAt time.Time
	MasterKey []byte
}

var activeSessions = make(map[string]*SessionInfo)

// stringPtr returns a pointer to a string
func stringPtr(s string) *string {
	return &s
}

// timePtr returns a pointer to a time
func timePtr(t time.Time) *time.Time {
	return &t
}

// Authenticate validates the master passphrase and issues a JWT token
func (a *AuthService) Authenticate(ctx context.Context, req *vault.AuthenticateRequest) (*vault.AuthenticateResponse, error) {
	if req.Passphrase == "" {
		return nil, status.Error(codes.InvalidArgument, "passphrase is required")
	}

	if req.DeviceId == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required")
	}

	passphrase := []byte(req.Passphrase)
	defer crypto.SecureZero(passphrase)

	masterKey, _, err := a.validateOrCreateMasterKey(ctx, passphrase)
	if err != nil {
		a.logAuditEvent(ctx, &store.AuditLog{
			Operation:        "authenticate",
			UserID:           req.DeviceId,
			DeviceID:         req.DeviceId,
			ClientIP:         stringPtr(getClientIP(ctx)),
			UserAgent:        stringPtr(getUserAgent(ctx)),
			OperationDetails: map[string]string{
				"reason": "invalid_passphrase",
				"result": "failure",
			},
			Success:   false,
			Timestamp: time.Now(),
		})
		return nil, status.Error(codes.Unauthenticated, "invalid passphrase")
	}
	defer crypto.SecureZero(masterKey)

	sessionID := uuid.New().String()

	tokenLifetime := a.tokenLifetime
	if req.TokenLifetime != nil && req.TokenLifetime.AsDuration() > 0 {
		requested := req.TokenLifetime.AsDuration()
		if requested < tokenLifetime {
			tokenLifetime = requested
		}
	}

	expiresAt := time.Now().Add(tokenLifetime)
	token, err := a.generateToken(req.DeviceId, sessionID, expiresAt)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	refreshToken, err := a.generateRefreshToken(req.DeviceId, sessionID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate refresh token")
	}

	encryptedMasterKey, err := a.encryptMasterKeyForSession(masterKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to secure session")
	}

	activeSessions[sessionID] = &SessionInfo{
		SessionID: sessionID,
		DeviceID:  req.DeviceId,
		ExpiresAt: expiresAt,
		MasterKey: encryptedMasterKey,
	}

	if err := a.registerDevice(ctx, req.DeviceId, req.DeviceInfo); err != nil {
		fmt.Printf("Warning: failed to register device: %v\n", err)
	}

	a.logAuditEvent(ctx, &store.AuditLog{
		Operation:        "authenticate",
		UserID:           req.DeviceId,
		DeviceID:         req.DeviceId,
		ClientIP:         stringPtr(getClientIP(ctx)),
		UserAgent:        stringPtr(getUserAgent(ctx)),
		OperationDetails: map[string]string{
			"session_id": sessionID,
			"result":     "success",
			"expires_at": expiresAt.Format(time.RFC3339),
		},
		Success:   true,
		SessionID: stringPtr(sessionID),
		Timestamp: time.Now(),
	})

	return &vault.AuthenticateResponse{
		Token:        token,
		ExpiresAt:    timestamppb.New(expiresAt),
		RefreshToken: refreshToken,
		Capabilities: &vault.ServerCapabilities{
			MaxTokenLifetime:            durationpb.New(a.tokenLifetime),
			MaxSecretSize:               1024 * 1024,
			SupportedEncryptionVersions: []uint32{1},
			MaxSecrets:                  10000,
			AuditEnabled:                true,
		},
	}, nil
}
