package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestRandomConstants(t *testing.T) {
	if MinTokenLength < 16 {
		t.Errorf("MinTokenLength should be at least 16, got %d", MinTokenLength)
	}
	
	if DefaultTokenLength < MinTokenLength {
		t.Errorf("DefaultTokenLength should be at least MinTokenLength, got %d", DefaultTokenLength)
	}
	
	if MaxTokenLength < DefaultTokenLength {
		t.Errorf("MaxTokenLength should be at least DefaultTokenLength, got %d", MaxTokenLength)
	}
}

func TestDefaultRandomConfig(t *testing.T) {
	config := DefaultRandomConfig()
	
	if config.MinEntropy < 128 {
		t.Errorf("Default minimum entropy should be at least 128 bits, got %d", config.MinEntropy)
	}
	
	if config.Source != nil {
		t.Error("Default config should use crypto/rand.Reader (Source should be nil)")
	}
}

func TestTestRandomConfig(t *testing.T) {
	config := TestRandomConfig()
	
	if config.MinEntropy >= DefaultRandomConfig().MinEntropy {
		t.Error("Test config should have lower entropy requirements than default")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{
			name:    "valid 16 bytes",
			length:  16,
			wantErr: false,
		},
		{
			name:    "valid 32 bytes",
			length:  32,
			wantErr: false,
		},
		{
			name:    "zero length",
			length:  0,
			wantErr: true,
		},
		{
			name:    "negative length",
			length:  -1,
			wantErr: true,
		},
		{
			name:    "too large",
			length:  MaxTokenLength + 1,
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := GenerateRandomBytes(tt.length)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRandomBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if len(data) != tt.length {
					t.Errorf("Generated data length = %d, expected %d", len(data), tt.length)
				}
				
				// Check that data is not all zeros (extremely unlikely)
				allZeros := true
				for _, b := range data {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros && tt.length > 0 {
					t.Error("Generated data is all zeros - likely not random")
				}
			}
		})
	}
}

func TestGenerateRandomBytesUniqueness(t *testing.T) {
	const numTests = 100
	const dataLength = 32
	
	generated := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		data, err := GenerateRandomBytes(dataLength)
		if err != nil {
			t.Fatalf("GenerateRandomBytes() failed on iteration %d: %v", i, err)
		}
		generated[i] = data
	}
	
	// Check for duplicates
	for i := 0; i < numTests; i++ {
		for j := i + 1; j < numTests; j++ {
			if bytes.Equal(generated[i], generated[j]) {
				t.Errorf("Found duplicate random data at indices %d and %d", i, j)
			}
		}
	}
}

func TestGenerateRandomBytesWithConfig(t *testing.T) {
	// Test with custom config
	config := RandomConfig{
		MinEntropy: 64,
		Source:     nil,
	}
	
	data, err := GenerateRandomBytesWithConfig(16, config) // 16 bytes = 128 bits > 64 bits required
	if err != nil {
		t.Fatalf("GenerateRandomBytesWithConfig() failed: %v", err)
	}
	
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}
	
	// Test insufficient entropy
	_, err = GenerateRandomBytesWithConfig(4, config) // 4 bytes = 32 bits < 64 bits required
	if err == nil {
		t.Error("GenerateRandomBytesWithConfig() should fail with insufficient entropy")
	}
}

func TestGenerateRandomBytesWithMockSource(t *testing.T) {
	// Mock source that returns predictable data
	mockData := []byte{0x01, 0x02, 0x03, 0x04}
	mockSource := func(data []byte) (int, error) {
		if len(data) > len(mockData) {
			return 0, errors.New("mock data too short")
		}
		copy(data, mockData[:len(data)])
		return len(data), nil
	}
	
	config := RandomConfig{
		MinEntropy: 16, // Low entropy for testing
		Source:     mockSource,
	}
	
	data, err := GenerateRandomBytesWithConfig(4, config)
	if err != nil {
		t.Fatalf("GenerateRandomBytesWithConfig() with mock source failed: %v", err)
	}
	
	expected := mockData[:4]
	if !bytes.Equal(data, expected) {
		t.Errorf("Mock source data mismatch: got %v, expected %v", data, expected)
	}
}

func TestGenerateSecureToken(t *testing.T) {
	tests := []struct {
		name   string
		length int
		format TokenFormat
		wantErr bool
	}{
		{
			name:   "valid hex token",
			length: 32,
			format: TokenFormatHex,
			wantErr: false,
		},
		{
			name:   "valid base64 token",
			length: 32,
			format: TokenFormatBase64,
			wantErr: false,
		},
		{
			name:   "valid base64url token",
			length: 32,
			format: TokenFormatBase64URL,
			wantErr: false,
		},
		{
			name:   "valid alphanumeric token",
			length: 32,
			format: TokenFormatAlphanumeric,
			wantErr: false,
		},
		{
			name:   "too short",
			length: MinTokenLength - 1,
			format: TokenFormatHex,
			wantErr: true,
		},
		{
			name:   "too long",
			length: MaxTokenLength + 1,
			format: TokenFormatHex,
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.length, tt.format)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSecureToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if len(token) != tt.length {
					t.Errorf("Token length = %d, expected %d", len(token), tt.length)
				}
				
				// Validate format
				if err := ValidateTokenFormat(token, tt.length, tt.format); err != nil {
					t.Errorf("Generated token has invalid format: %v", err)
				}
			}
		})
	}
}

func TestGenerateSecureTokenUniqueness(t *testing.T) {
	const numTokens = 50
	const tokenLength = 32
	
	tokens := make([]string, numTokens)
	for i := 0; i < numTokens; i++ {
		token, err := GenerateSecureToken(tokenLength, TokenFormatHex)
		if err != nil {
			t.Fatalf("GenerateSecureToken() failed on iteration %d: %v", i, err)
		}
		tokens[i] = token
	}
	
	// Check for duplicates
	for i := 0; i < numTokens; i++ {
		for j := i + 1; j < numTokens; j++ {
			if tokens[i] == tokens[j] {
				t.Errorf("Found duplicate token at indices %d and %d: %s", i, j, tokens[i])
			}
		}
	}
}

func TestTokenFormats(t *testing.T) {
	const tokenLength = 32
	
	// Test hex format
	hexToken, err := GenerateSecureToken(tokenLength, TokenFormatHex)
	if err != nil {
		t.Fatalf("Failed to generate hex token: %v", err)
	}
	
	// Verify hex token contains only hex characters
	for _, char := range hexToken {
		if !isHexChar(char) {
			t.Errorf("Hex token contains non-hex character: %c", char)
		}
	}
	
	// Test that hex token can be decoded
	_, err = hex.DecodeString(hexToken)
	if err != nil {
		t.Errorf("Hex token cannot be decoded: %v", err)
	}
	
	// Test base64 format
	_, err = GenerateSecureToken(tokenLength, TokenFormatBase64)
	if err != nil {
		t.Fatalf("Failed to generate base64 token: %v", err)
	}
	
	// Test base64url format
	base64URLToken, err := GenerateSecureToken(tokenLength, TokenFormatBase64URL)
	if err != nil {
		t.Fatalf("Failed to generate base64url token: %v", err)
	}
	
	// Verify base64url token contains no padding and no +/
	if strings.Contains(base64URLToken, "=") || strings.Contains(base64URLToken, "+") || strings.Contains(base64URLToken, "/") {
		t.Errorf("Base64URL token contains invalid characters: %s", base64URLToken)
	}
	
	// Test alphanumeric format
	alphanumericToken, err := GenerateSecureToken(tokenLength, TokenFormatAlphanumeric)
	if err != nil {
		t.Fatalf("Failed to generate alphanumeric token: %v", err)
	}
	
	// Verify alphanumeric token contains only allowed characters
	for _, char := range alphanumericToken {
		if !isAlphanumericChar(char) {
			t.Errorf("Alphanumeric token contains invalid character: %c", char)
		}
	}
}

func TestConvenienceFunctions(t *testing.T) {
	// Test GenerateSessionToken
	sessionToken, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken() failed: %v", err)
	}
	
	if len(sessionToken) != DefaultTokenLength {
		t.Errorf("Session token length = %d, expected %d", len(sessionToken), DefaultTokenLength)
	}
	
	if err := ValidateTokenFormat(sessionToken, DefaultTokenLength, TokenFormatBase64URL); err != nil {
		t.Errorf("Session token has invalid format: %v", err)
	}
	
	// Test GenerateAPIKey
	apiKey, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey() failed: %v", err)
	}
	
	if len(apiKey) != 64 {
		t.Errorf("API key length = %d, expected 64", len(apiKey))
	}
	
	if err := ValidateTokenFormat(apiKey, 64, TokenFormatHex); err != nil {
		t.Errorf("API key has invalid format: %v", err)
	}
	
	// Test GenerateDeviceID
	deviceID, err := GenerateDeviceID()
	if err != nil {
		t.Fatalf("GenerateDeviceID() failed: %v", err)
	}
	
	if len(deviceID) != 24 {
		t.Errorf("Device ID length = %d, expected 24", len(deviceID))
	}
	
	if err := ValidateTokenFormat(deviceID, 24, TokenFormatAlphanumeric); err != nil {
		t.Errorf("Device ID has invalid format: %v", err)
	}
	
	// Test GenerateCSRFToken
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken() failed: %v", err)
	}
	
	if len(csrfToken) != 32 {
		t.Errorf("CSRF token length = %d, expected 32", len(csrfToken))
	}
	
	if err := ValidateTokenFormat(csrfToken, 32, TokenFormatBase64URL); err != nil {
		t.Errorf("CSRF token has invalid format: %v", err)
	}
}

func TestGenerateRandomID(t *testing.T) {
	// Test with prefix
	id, err := GenerateRandomID("user")
	if err != nil {
		t.Fatalf("GenerateRandomID() with prefix failed: %v", err)
	}
	
	if !strings.HasPrefix(id, "user_") {
		t.Errorf("ID should start with 'user_', got: %s", id)
	}
	
	parts := strings.Split(id, "_")
	if len(parts) != 2 {
		t.Errorf("ID should have exactly one underscore, got: %s", id)
	}
	
	randomPart := parts[1]
	if len(randomPart) != 16 {
		t.Errorf("Random part should be 16 characters, got %d", len(randomPart))
	}
	
	// Test without prefix
	id2, err := GenerateRandomID("")
	if err != nil {
		t.Fatalf("GenerateRandomID() without prefix failed: %v", err)
	}
	
	if len(id2) != 16 {
		t.Errorf("ID without prefix should be 16 characters, got %d", len(id2))
	}
	
	if strings.Contains(id2, "_") {
		t.Errorf("ID without prefix should not contain underscore, got: %s", id2)
	}
}

func TestValidateTokenFormat(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		expectedLength int
		format         TokenFormat
		wantErr        bool
	}{
		{
			name:           "valid hex token",
			token:          "deadbeef123456789abcdef0",
			expectedLength: 24,
			format:         TokenFormatHex,
			wantErr:        false,
		},
		{
			name:           "invalid hex token - contains g",
			token:          "deadbeefg23456789abcdef0",
			expectedLength: 24,
			format:         TokenFormatHex,
			wantErr:        true,
		},
		{
			name:           "wrong length",
			token:          "deadbeef",
			expectedLength: 16,
			format:         TokenFormatHex,
			wantErr:        true,
		},
		{
			name:           "valid base64url token",
			token:          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
			expectedLength: 32,
			format:         TokenFormatBase64URL,
			wantErr:        false,
		},
		{
			name:           "invalid base64url token - contains +",
			token:          "ABCDEFGHIJKLMNOPQRSTUVWXYZ+bcdef",
			expectedLength: 32,
			format:         TokenFormatBase64URL,
			wantErr:        true,
		},
		{
			name:           "valid alphanumeric token",
			token:          "ABC123def456GHI789jkl012MNO34567",
			expectedLength: 32,
			format:         TokenFormatAlphanumeric,
			wantErr:        false,
		},
		{
			name:           "invalid alphanumeric token - contains underscore",
			token:          "ABC123def456GHI789jkl012MNO34_",
			expectedLength: 32,
			format:         TokenFormatAlphanumeric,
			wantErr:        true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTokenFormat(tt.token, tt.expectedLength, tt.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTokenFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCharacterValidationHelpers(t *testing.T) {
	// Test isHexChar
	hexChars := "0123456789abcdefABCDEF"
	for _, char := range hexChars {
		if !isHexChar(char) {
			t.Errorf("isHexChar() failed for valid hex char: %c", char)
		}
	}
	
	invalidHexChars := "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ!@#$%"
	for _, char := range invalidHexChars {
		if isHexChar(char) {
			t.Errorf("isHexChar() incorrectly validated invalid hex char: %c", char)
		}
	}
	
	// Test isAlphanumericChar
	alphanumericChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for _, char := range alphanumericChars {
		if !isAlphanumericChar(char) {
			t.Errorf("isAlphanumericChar() failed for valid alphanumeric char: %c", char)
		}
	}
	
	invalidAlphanumericChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, char := range invalidAlphanumericChars {
		if isAlphanumericChar(char) {
			t.Errorf("isAlphanumericChar() incorrectly validated invalid alphanumeric char: %c", char)
		}
	}
}

func TestCalculateTokenLengthForEntropy(t *testing.T) {
	tests := []struct {
		name           string
		desiredEntropy int
		alphabetSize   int
		expectedMin    int
	}{
		{
			name:           "128 bits with hex (16 chars)",
			desiredEntropy: 128,
			alphabetSize:   16,
			expectedMin:    32, // 128 / 4 = 32
		},
		{
			name:           "256 bits with base64 (64 chars)", 
			desiredEntropy: 256,
			alphabetSize:   64,
			expectedMin:    43, // 256 / 6 ≈ 42.67, rounded up to 43
		},
		{
			name:           "zero entropy",
			desiredEntropy: 0,
			alphabetSize:   16,
			expectedMin:    0,
		},
		{
			name:           "invalid alphabet size",
			desiredEntropy: 128,
			alphabetSize:   1,
			expectedMin:    0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateTokenLengthForEntropy(tt.desiredEntropy, tt.alphabetSize)
			if result < tt.expectedMin {
				t.Errorf("CalculateTokenLengthForEntropy() = %d, expected at least %d", result, tt.expectedMin)
			}
		})
	}
}

// Benchmark tests
func BenchmarkGenerateRandomBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateRandomBytes(32)
		if err != nil {
			b.Fatalf("GenerateRandomBytes() failed: %v", err)
		}
	}
}

func BenchmarkGenerateSecureTokenHex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSecureToken(32, TokenFormatHex)
		if err != nil {
			b.Fatalf("GenerateSecureToken() failed: %v", err)
		}
	}
}

func BenchmarkGenerateSecureTokenBase64URL(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSecureToken(32, TokenFormatBase64URL)
		if err != nil {
			b.Fatalf("GenerateSecureToken() failed: %v", err)
		}
	}
}

func BenchmarkGenerateSecureTokenAlphanumeric(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSecureToken(32, TokenFormatAlphanumeric)
		if err != nil {
			b.Fatalf("GenerateSecureToken() failed: %v", err)
		}
	}
}

func BenchmarkGenerateSessionToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSessionToken()
		if err != nil {
			b.Fatalf("GenerateSessionToken() failed: %v", err)
		}
	}
}