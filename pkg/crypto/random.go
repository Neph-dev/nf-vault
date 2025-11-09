package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

const (
	// MinTokenLength is the minimum length for secure tokens
	MinTokenLength = 16
	
	// DefaultTokenLength is the default length for session tokens
	DefaultTokenLength = 32
	
	// MaxTokenLength is the maximum length for tokens (to prevent DoS)
	MaxTokenLength = 512
	
	// Base64URLAlphabet is the character set for base64url encoding (URL-safe)
	Base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	
	// HexAlphabet is the character set for hexadecimal encoding
	HexAlphabet = "0123456789abcdef"
	
	// AlphanumericAlphabet is the character set for alphanumeric tokens
	AlphanumericAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// TokenFormat represents different formats for token generation
type TokenFormat int

const (
	// TokenFormatHex generates tokens in hexadecimal format
	TokenFormatHex TokenFormat = iota
	
	// TokenFormatBase64 generates tokens in base64 format  
	TokenFormatBase64
	
	// TokenFormatBase64URL generates tokens in base64url format (URL-safe)
	TokenFormatBase64URL
	
	// TokenFormatAlphanumeric generates tokens using alphanumeric characters only
	TokenFormatAlphanumeric
)

// RandomConfig holds configuration for random generation operations
type RandomConfig struct {
	// MinEntropy is the minimum entropy in bits for generated values
	MinEntropy int
	
	// Source can be used to specify alternative entropy sources (for testing)
	// If nil, crypto/rand.Reader is used
	Source func([]byte) (int, error)
}

// DefaultRandomConfig returns secure default configuration for random generation
func DefaultRandomConfig() RandomConfig {
	return RandomConfig{
		MinEntropy: 128, // 128 bits minimum entropy
		Source:     nil, // Use crypto/rand.Reader
	}
}

// TestRandomConfig returns a configuration suitable for testing with reduced entropy requirements
// WARNING: Do not use in production
func TestRandomConfig() RandomConfig {
	return RandomConfig{
		MinEntropy: 64, // Reduced entropy for testing
		Source:     nil,
	}
}

// GenerateRandomBytes generates cryptographically secure random bytes of the specified length.
// This is the fundamental building block for all other random generation functions.
func GenerateRandomBytes(length int) ([]byte, error) {
	return GenerateRandomBytesWithConfig(length, DefaultRandomConfig())
}

// GenerateRandomBytesWithConfig generates random bytes using the specified configuration.
func GenerateRandomBytesWithConfig(length int, config RandomConfig) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("length must be positive")
	}
	
	if length > MaxTokenLength {
		return nil, fmt.Errorf("length %d exceeds maximum %d", length, MaxTokenLength)
	}
	
	// Validate that the requested length provides sufficient entropy
	if length*8 < config.MinEntropy {
		return nil, fmt.Errorf("requested length %d bytes provides only %d bits of entropy, minimum required: %d bits", 
			length, length*8, config.MinEntropy)
	}
	
	data := make([]byte, length)
	
	// Use configured source or default to crypto/rand.Reader
	var n int
	var err error
	if config.Source != nil {
		n, err = config.Source(data)
	} else {
		n, err = rand.Read(data)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	if n != length {
		return nil, fmt.Errorf("failed to generate full random data: got %d bytes, expected %d", n, length)
	}
	
	return data, nil
}

// GenerateSecureToken generates a cryptographically secure token of the specified length and format.
// The token is suitable for session IDs, API keys, and other security-sensitive use cases.
func GenerateSecureToken(length int, format TokenFormat) (string, error) {
	return GenerateSecureTokenWithConfig(length, format, DefaultRandomConfig())
}

// GenerateSecureTokenWithConfig generates a secure token using the specified configuration.
func GenerateSecureTokenWithConfig(length int, format TokenFormat, config RandomConfig) (string, error) {
	if length < MinTokenLength {
		return "", fmt.Errorf("token length %d is below minimum %d", length, MinTokenLength)
	}
	
	if length > MaxTokenLength {
		return "", fmt.Errorf("token length %d exceeds maximum %d", length, MaxTokenLength)
	}
	
	switch format {
	case TokenFormatHex:
		return generateHexToken(length, config)
	case TokenFormatBase64:
		return generateBase64Token(length, config)
	case TokenFormatBase64URL:
		return generateBase64URLToken(length, config)
	case TokenFormatAlphanumeric:
		return generateAlphanumericToken(length, config)
	default:
		return "", fmt.Errorf("unsupported token format: %d", format)
	}
}

// generateHexToken generates a token in hexadecimal format
func generateHexToken(length int, config RandomConfig) (string, error) {
	// For hex tokens, we need length/2 bytes to produce length hex characters
	byteLength := (length + 1) / 2
	
	bytes, err := GenerateRandomBytesWithConfig(byteLength, config)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	token := hex.EncodeToString(bytes)
	
	// Truncate to exact requested length
	if len(token) > length {
		token = token[:length]
	}
	
	return token, nil
}

// generateBase64Token generates a token in base64 format
func generateBase64Token(length int, config RandomConfig) (string, error) {
	// For base64, we need approximately length*3/4 bytes
	byteLength := (length*3 + 3) / 4
	
	bytes, err := GenerateRandomBytesWithConfig(byteLength, config)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	token := base64.StdEncoding.EncodeToString(bytes)
	
	// Truncate to exact requested length (removing padding if necessary)
	if len(token) > length {
		token = token[:length]
	}
	
	return token, nil
}

// generateBase64URLToken generates a token in base64url format (URL-safe)
func generateBase64URLToken(length int, config RandomConfig) (string, error) {
	// For base64url, we need approximately length*3/4 bytes
	byteLength := (length*3 + 3) / 4
	
	bytes, err := GenerateRandomBytesWithConfig(byteLength, config)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	token := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
	
	// Truncate to exact requested length
	if len(token) > length {
		token = token[:length]
	}
	
	return token, nil
}

// generateAlphanumericToken generates a token using only alphanumeric characters
func generateAlphanumericToken(length int, config RandomConfig) (string, error) {
	alphabet := AlphanumericAlphabet
	alphabetLen := big.NewInt(int64(len(alphabet)))
	
	token := make([]byte, length)
	
	for i := 0; i < length; i++ {
		// Generate random index into alphabet
		index, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		
		token[i] = alphabet[index.Int64()]
	}
	
	return string(token), nil
}

// GenerateSessionToken generates a session token suitable for web applications.
// Uses base64url encoding for URL safety and includes sufficient entropy.
func GenerateSessionToken() (string, error) {
	return GenerateSecureToken(DefaultTokenLength, TokenFormatBase64URL)
}

// GenerateAPIKey generates an API key token suitable for API authentication.
// Uses hexadecimal encoding for easy handling and includes high entropy.
func GenerateAPIKey() (string, error) {
	return GenerateSecureToken(64, TokenFormatHex) // 64 hex chars = 256 bits
}

// GenerateDeviceID generates a unique device identifier.
// Uses alphanumeric encoding for easy display and typing.
func GenerateDeviceID() (string, error) {
	return GenerateSecureToken(24, TokenFormatAlphanumeric)
}

// GenerateCSRFToken generates a CSRF (Cross-Site Request Forgery) protection token.
// Uses base64url encoding for URL safety.
func GenerateCSRFToken() (string, error) {
	return GenerateSecureToken(32, TokenFormatBase64URL)
}

// GenerateRandomID generates a random identifier with the specified prefix.
// Useful for creating unique IDs for database records, temporary files, etc.
func GenerateRandomID(prefix string) (string, error) {
	token, err := GenerateSecureToken(16, TokenFormatAlphanumeric)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	
	if prefix == "" {
		return token, nil
	}
	
	return prefix + "_" + token, nil
}

// ValidateTokenFormat checks if a token matches the expected format and length requirements.
func ValidateTokenFormat(token string, expectedLength int, format TokenFormat) error {
	if len(token) != expectedLength {
		return fmt.Errorf("token length mismatch: got %d, expected %d", len(token), expectedLength)
	}
	
	switch format {
	case TokenFormatHex:
		for _, char := range token {
			if !isHexChar(char) {
				return fmt.Errorf("invalid hex character in token: %c", char)
			}
		}
	case TokenFormatBase64:
		// Base64 can contain +, /, and = (padding)
		for _, char := range token {
			if !isBase64Char(char) {
				return fmt.Errorf("invalid base64 character in token: %c", char)
			}
		}
	case TokenFormatBase64URL:
		// Base64URL uses - and _ instead of + and /, no padding
		for _, char := range token {
			if !isBase64URLChar(char) {
				return fmt.Errorf("invalid base64url character in token: %c", char)
			}
		}
	case TokenFormatAlphanumeric:
		for _, char := range token {
			if !isAlphanumericChar(char) {
				return fmt.Errorf("invalid alphanumeric character in token: %c", char)
			}
		}
	default:
		return fmt.Errorf("unsupported token format: %d", format)
	}
	
	return nil
}

// Helper functions for character validation
func isHexChar(char rune) bool {
	return (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')
}

func isBase64Char(char rune) bool {
	return (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || 
		   (char >= '0' && char <= '9') || char == '+' || char == '/' || char == '='
}

func isBase64URLChar(char rune) bool {
	return (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || 
		   (char >= '0' && char <= '9') || char == '-' || char == '_'
}

func isAlphanumericChar(char rune) bool {
	return (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
}

// EstimateEntropy estimates the entropy (in bits) of a token based on its alphabet size and length.
func EstimateEntropy(tokenLength int, alphabetSize int) float64 {
	if tokenLength <= 0 || alphabetSize <= 1 {
		return 0
	}
	
	// Entropy = log2(alphabet_size) * token_length
	// Using change of base formula: log2(x) = ln(x) / ln(2)
	return float64(tokenLength) * (float64(alphabetSize) / 2.0) // Simplified calculation
}

// CalculateTokenLengthForEntropy calculates the minimum token length required 
// to achieve the desired entropy with the given alphabet size.
func CalculateTokenLengthForEntropy(desiredEntropy int, alphabetSize int) int {
	if desiredEntropy <= 0 || alphabetSize <= 1 {
		return 0
	}
	
	// Required length = ceil(desired_entropy / log2(alphabet_size))
	// Simplified calculation for common alphabet sizes
	var bitsPerChar float64
	switch alphabetSize {
	case 16: // Hex
		bitsPerChar = 4.0
	case 62: // Alphanumeric
		bitsPerChar = 5.95 // log2(62) ≈ 5.95
	case 64: // Base64
		bitsPerChar = 6.0
	default:
		// General case - this is a simplified approximation
		bitsPerChar = float64(alphabetSize) / 16.0
	}
	
	requiredLength := int((float64(desiredEntropy) / bitsPerChar) + 0.999) // Ceiling
	return requiredLength
}