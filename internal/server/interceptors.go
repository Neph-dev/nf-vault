package server

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthInterceptor handles authentication for gRPC requests
type AuthInterceptor struct {
	authService *AuthService
}

// NewAuthInterceptor creates a new authentication interceptor
func NewAuthInterceptor(authService *AuthService) *AuthInterceptor {
	return &AuthInterceptor{
		authService: authService,
	}
}

// UnaryInterceptor is the unary auth interceptor for single request-response RPCs
func (a *AuthInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Skip authentication for certain methods (like Authenticate itself)
	if isPublicMethod(info.FullMethod) {
		return handler(ctx, req)
	}

	// Extract and verify token
	token, err := extractTokenFromMetadata(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid token")
	}

	claims, err := a.authService.VerifyToken(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token: "+err.Error())
	}

	// Inject claims into context for use by the handler
	ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
	ctx = context.WithValue(ctx, "session_id", claims.SessionID)
	ctx = context.WithValue(ctx, "scope", claims.Scope)

	return handler(ctx, req)
}

// StreamInterceptor is the stream auth interceptor for streaming RPCs
func (a *AuthInterceptor) StreamInterceptor(
	srv interface{},
	stream grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	// Skip authentication for certain methods
	if isPublicMethod(info.FullMethod) {
		return handler(srv, stream)
	}

	// Extract and verify token
	token, err := extractTokenFromMetadata(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, "missing or invalid token")
	}

	claims, err := a.authService.VerifyToken(token)
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid token: "+err.Error())
	}

	// Create wrapped stream with authenticated context
	wrappedStream := &AuthenticatedServerStream{
		ServerStream: stream,
		ctx: context.WithValue(
			context.WithValue(
				context.WithValue(stream.Context(), "device_id", claims.DeviceID),
				"session_id", claims.SessionID),
			"scope", claims.Scope),
	}

	return handler(srv, wrappedStream)
}

// AuthenticatedServerStream wraps grpc.ServerStream with authenticated context
type AuthenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the authenticated context
func (w *AuthenticatedServerStream) Context() context.Context {
	return w.ctx
}

// LoggingInterceptor handles structured logging for gRPC requests
type LoggingInterceptor struct {
	logger *log.Logger
}

// NewLoggingInterceptor creates a new logging interceptor
func NewLoggingInterceptor(logger *log.Logger) *LoggingInterceptor {
	return &LoggingInterceptor{
		logger: logger,
	}
}

// UnaryInterceptor logs unary RPC calls
func (l *LoggingInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Generate unique request ID
	requestID := uuid.New().String()
	ctx = context.WithValue(ctx, "request_id", requestID)

	start := time.Now()

	// Extract client information
	clientIP := getClientIP(ctx)
	userAgent := getUserAgent(ctx)
	deviceID := getDeviceIDFromContext(ctx)

	// Log request start
	l.logger.Printf("RPC_START method=%s request_id=%s client_ip=%s user_agent=%s device_id=%s",
		info.FullMethod, requestID, clientIP, userAgent, deviceID)

	// Call the handler
	resp, err := handler(ctx, req)

	// Calculate duration
	duration := time.Since(start)

	// Log request completion
	if err != nil {
		status := status.Code(err)
		l.logger.Printf("RPC_ERROR method=%s request_id=%s duration=%v status=%s error=%v",
			info.FullMethod, requestID, duration, status.String(), err)
	} else {
		l.logger.Printf("RPC_SUCCESS method=%s request_id=%s duration=%v",
			info.FullMethod, requestID, duration)
	}

	return resp, err
}

// StreamInterceptor logs streaming RPC calls
func (l *LoggingInterceptor) StreamInterceptor(
	srv interface{},
	stream grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	// Generate unique request ID
	requestID := uuid.New().String()
	ctx := context.WithValue(stream.Context(), "request_id", requestID)

	start := time.Now()

	// Extract client information
	clientIP := getClientIP(ctx)
	userAgent := getUserAgent(ctx)
	deviceID := getDeviceIDFromContext(ctx)

	// Log stream start
	l.logger.Printf("STREAM_START method=%s request_id=%s client_ip=%s user_agent=%s device_id=%s",
		info.FullMethod, requestID, clientIP, userAgent, deviceID)

	// Create wrapped stream with request ID
	wrappedStream := &LoggedServerStream{
		ServerStream: stream,
		ctx:          ctx,
	}

	// Call the handler
	err := handler(srv, wrappedStream)

	// Calculate duration
	duration := time.Since(start)

	// Log stream completion
	if err != nil {
		status := status.Code(err)
		l.logger.Printf("STREAM_ERROR method=%s request_id=%s duration=%v status=%s error=%v",
			info.FullMethod, requestID, duration, status.String(), err)
	} else {
		l.logger.Printf("STREAM_SUCCESS method=%s request_id=%s duration=%v",
			info.FullMethod, requestID, duration)
	}

	return err
}

// LoggedServerStream wraps grpc.ServerStream with logging context
type LoggedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the context with request ID
func (w *LoggedServerStream) Context() context.Context {
	return w.ctx
}

// ErrorHandlingInterceptor sanitizes errors to prevent information leakage
type ErrorHandlingInterceptor struct{}

// NewErrorHandlingInterceptor creates a new error handling interceptor
func NewErrorHandlingInterceptor() *ErrorHandlingInterceptor {
	return &ErrorHandlingInterceptor{}
}

// UnaryInterceptor handles error sanitization for unary RPCs
func (e *ErrorHandlingInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	resp, err := handler(ctx, req)
	if err != nil {
		return resp, sanitizeError(err)
	}
	return resp, nil
}

// StreamInterceptor handles error sanitization for streaming RPCs
func (e *ErrorHandlingInterceptor) StreamInterceptor(
	srv interface{},
	stream grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	err := handler(srv, stream)
	if err != nil {
		return sanitizeError(err)
	}
	return nil
}

// Helper functions

// isPublicMethod checks if a method should skip authentication
func isPublicMethod(method string) bool {
	publicMethods := []string{
		"/vault.v1.VaultService/Authenticate",
		"/vault.v1.VaultService/Health",
	}

	for _, publicMethod := range publicMethods {
		if method == publicMethod {
			return true
		}
	}
	return false
}

// extractTokenFromMetadata extracts the authorization token from gRPC metadata
func extractTokenFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Check for Authorization header with Bearer token
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", status.Error(codes.Unauthenticated, "invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", status.Error(codes.Unauthenticated, "empty token")
	}

	return token, nil
}

// sanitizeError removes sensitive information from errors before returning to clients
func sanitizeError(err error) error {
	// Convert to gRPC status
	st, ok := status.FromError(err)
	if !ok {
		// If it's not already a gRPC status, convert it
		return status.Error(codes.Internal, "internal server error")
	}

	// Sanitize certain error codes and messages
	switch st.Code() {
	case codes.Internal:
		// Never expose internal errors
		return status.Error(codes.Internal, "internal server error")
	case codes.Unknown:
		// Convert unknown errors to internal
		return status.Error(codes.Internal, "internal server error")
	case codes.Unauthenticated:
		// Sanitize authentication errors to prevent enumeration
		return status.Error(codes.Unauthenticated, "authentication failed")
	case codes.PermissionDenied:
		// Keep permission denied but sanitize message
		return status.Error(codes.PermissionDenied, "access denied")
	case codes.NotFound:
		// Generic not found message
		return status.Error(codes.NotFound, "resource not found")
	case codes.AlreadyExists:
		// Generic already exists message
		return status.Error(codes.AlreadyExists, "resource already exists")
	case codes.InvalidArgument:
		// Keep invalid argument but sanitize sensitive details
		message := st.Message()
		if containsSensitiveInfo(message) {
			return status.Error(codes.InvalidArgument, "invalid request")
		}
		return err
	default:
		// For other codes, keep the error but sanitize the message
		message := st.Message()
		if containsSensitiveInfo(message) {
			return status.Error(st.Code(), "operation failed")
		}
		return err
	}
}

// containsSensitiveInfo checks if an error message contains sensitive information
func containsSensitiveInfo(message string) bool {
	sensitiveKeywords := []string{
		"password", "passphrase", "secret", "key", "token",
		"salt", "hash", "credential", "private", "confidential",
		"sql", "database", "table", "column", "query",
		"file", "path", "directory", "folder",
		"stack trace", "panic", "runtime",
	}

	lowerMessage := strings.ToLower(message)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerMessage, keyword) {
			return true
		}
	}
	return false
}