package crypto

import (
	"bytes"
	"testing"
)

// FuzzDeriveKey tests key derivation with malformed inputs
func FuzzDeriveKey(f *testing.F) {
	// Seed with valid test cases
	f.Add([]byte("valid-passphrase"), []byte("0123456789abcdef0123456789abcdef"), uint32(1), uint32(65536), uint8(1), uint32(32), uint32(32))
	f.Add([]byte(""), []byte("0123456789abcdef0123456789abcdef"), uint32(1), uint32(65536), uint8(1), uint32(32), uint32(32))
	f.Add([]byte("test"), []byte("short"), uint32(1), uint32(65536), uint8(1), uint32(32), uint32(32))
	f.Add([]byte("fuzz-test-passphrase"), []byte("0123456789abcdef0123456789abcdef"), uint32(0), uint32(65536), uint8(1), uint32(32), uint32(32))
	f.Add([]byte("fuzz-test-passphrase"), []byte("0123456789abcdef0123456789abcdef"), uint32(1), uint32(1000), uint8(1), uint32(32), uint32(32))
	
	f.Fuzz(func(t *testing.T, passphrase []byte, salt []byte, time uint32, memory uint32, threads uint8, keyLen uint32, saltLen uint32) {
		// Limit input sizes to prevent resource exhaustion
		if len(passphrase) > 1000 {
			passphrase = passphrase[:1000]
		}
		if len(salt) > 1000 {
			salt = salt[:1000]
		}
		if keyLen > 1024 {
			keyLen = 1024
		}
		if saltLen > 1024 {
			saltLen = 1024
		}
		if memory > 1048576 { // Limit to 1GB
			memory = 1048576
		}
		
		params := KDFParams{
			Time:    time,
			Memory:  memory,
			Threads: threads,
			KeyLen:  keyLen,
			SaltLen: saltLen,
		}
		
		// DeriveKey should never panic, regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DeriveKey panicked with input: passphrase=%q, salt=%q, params=%+v", 
					string(passphrase), string(salt), params)
			}
		}()
		
		key, err := DeriveKey(passphrase, salt, params)
		
		// If the function succeeds, the output should be valid
		if err == nil {
			if len(key) != int(keyLen) {
				t.Errorf("Key length mismatch: got %d, expected %d", len(key), keyLen)
			}
			
			// Key should not be all zeros (unless keyLen is 0)
			if keyLen > 0 {
				allZeros := true
				for _, b := range key {
					if b != 0 {
						allZeros = false
						break
					}
				}
				// It's extremely unlikely but theoretically possible for a valid key to be all zeros
				// So we just log this case rather than failing
				if allZeros {
					t.Logf("Generated all-zero key (rare but possible): params=%+v", params)
				}
			}
		}
		
		// Test deterministic behavior: same inputs should produce same results
		if err == nil {
			key2, err2 := DeriveKey(passphrase, salt, params)
			if err2 == nil && !bytes.Equal(key, key2) {
				t.Errorf("DeriveKey is not deterministic")
			}
		}
	})
}

// FuzzGenerateSalt tests salt generation with various lengths
func FuzzGenerateSalt(f *testing.F) {
	// Seed with common salt lengths
	f.Add(uint32(16))
	f.Add(uint32(32))
	f.Add(uint32(0))
	f.Add(uint32(1))
	f.Add(uint32(1024))
	
	f.Fuzz(func(t *testing.T, length uint32) {
		// Limit length to prevent resource exhaustion
		if length > 10000 {
			length = 10000
		}
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GenerateSalt panicked with length %d", length)
			}
		}()
		
		salt, err := GenerateSalt(length)
		
		if err == nil {
			if len(salt) != int(length) {
				t.Errorf("Salt length mismatch: got %d, expected %d", len(salt), length)
			}
			
			// For non-zero lengths, salt should not be all zeros (extremely unlikely)
			if length > 0 {
				allZeros := true
				for _, b := range salt {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Logf("Generated all-zero salt of length %d (rare but possible)", length)
				}
			}
		}
		
		// Zero length should always fail
		if length == 0 && err == nil {
			t.Error("GenerateSalt should fail with zero length")
		}
	})
}

// FuzzEncryptSecret tests secret encryption with various input sizes and content
func FuzzEncryptSecret(f *testing.F) {
	// Generate a valid master key for testing
	masterKey, err := GenerateDataKey()
	if err != nil {
		f.Fatalf("Failed to generate master key: %v", err)
	}
	
	// Seed with various secret data
	f.Add(masterKey, []byte("test secret"))
	f.Add(masterKey, []byte(""))
	f.Add(masterKey, []byte("a"))
	f.Add(masterKey, bytes.Repeat([]byte("x"), 1000))
	f.Add(masterKey, []byte{0, 1, 2, 3, 255, 254, 253})
	
	f.Fuzz(func(t *testing.T, key []byte, secretData []byte) {
		// Limit secret size to prevent resource exhaustion
		if len(secretData) > 100000 { // 100KB limit
			secretData = secretData[:100000]
		}
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("EncryptSecret panicked with key len=%d, secret len=%d", 
					len(key), len(secretData))
			}
		}()
		
		encrypted, err := EncryptSecret(key, secretData)
		
		if err == nil {
			// If encryption succeeds, we should be able to decrypt
			decrypted, decErr := DecryptSecret(key, encrypted)
			if decErr != nil {
				t.Errorf("Failed to decrypt successfully encrypted secret: %v", decErr)
			} else if !bytes.Equal(secretData, decrypted) {
				t.Errorf("Decrypted data doesn't match original")
			}
			
			// Validate encrypted secret structure
			if validateErr := ValidateEncryptedSecret(encrypted); validateErr != nil {
				t.Errorf("Encrypted secret failed validation: %v", validateErr)
			}
		}
		
		// Empty secret data should always fail
		if len(secretData) == 0 && err == nil {
			t.Error("EncryptSecret should fail with empty secret data")
		}
		
		// Wrong key size should always fail
		if len(key) != AESKeySize && err == nil {
			t.Error("EncryptSecret should fail with wrong key size")
		}
	})
}

// FuzzDecryptSecret tests secret decryption with malformed encrypted data
func FuzzDecryptSecret(f *testing.F) {
	// Generate a valid master key and encrypted secret for testing
	masterKey, err := GenerateDataKey()
	if err != nil {
		f.Fatalf("Failed to generate master key: %v", err)
	}
	
	validSecret, err := EncryptSecret(masterKey, []byte("test secret"))
	if err != nil {
		f.Fatalf("Failed to encrypt test secret: %v", err)
	}
	
	// Seed with various encrypted secret structures
	f.Add(masterKey, validSecret.EncryptedDataKey, validSecret.EncryptedData, validSecret.Version)
	f.Add(masterKey, []byte("short"), validSecret.EncryptedData, validSecret.Version)
	f.Add(masterKey, validSecret.EncryptedDataKey, []byte("short"), validSecret.Version)
	f.Add(masterKey, validSecret.EncryptedDataKey, validSecret.EncryptedData, uint32(0))
	f.Add(masterKey, validSecret.EncryptedDataKey, validSecret.EncryptedData, uint32(999))
	
	f.Fuzz(func(t *testing.T, key []byte, encDataKey []byte, encData []byte, version uint32) {
		// Limit sizes to prevent resource exhaustion
		if len(encDataKey) > 10000 {
			encDataKey = encDataKey[:10000]
		}
		if len(encData) > 100000 {
			encData = encData[:100000]
		}
		
		encrypted := &EncryptedSecret{
			EncryptedDataKey: encDataKey,
			EncryptedData:    encData,
			Version:          version,
		}
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DecryptSecret panicked with key len=%d, encDataKey len=%d, encData len=%d, version=%d", 
					len(key), len(encDataKey), len(encData), version)
			}
		}()
		
		_, _ = DecryptSecret(key, encrypted)
		
		// DecryptSecret should handle all malformed inputs gracefully (return error, not panic)
		// We don't check the specific error because there are many valid reasons for failure
		
		// Test with nil encrypted secret
		_, nilErr := DecryptSecret(key, nil)
		if nilErr == nil {
			t.Error("DecryptSecret should fail with nil encrypted secret")
		}
	})
}

// FuzzGenerateRandomBytes tests random byte generation with various lengths
func FuzzGenerateRandomBytes(f *testing.F) {
	// Seed with various lengths
	f.Add(int(16))
	f.Add(int(32))
	f.Add(int(0))
	f.Add(int(-1))
	f.Add(int(1000))
	
	f.Fuzz(func(t *testing.T, length int) {
		// Limit length to prevent resource exhaustion
		if length > 50000 {
			length = 50000
		}
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GenerateRandomBytes panicked with length %d", length)
			}
		}()
		
		data, err := GenerateRandomBytes(length)
		
		if err == nil {
			if len(data) != length {
				t.Errorf("Random data length mismatch: got %d, expected %d", len(data), length)
			}
			
			// For reasonable lengths, data should not be all zeros
			if length > 0 && length <= 1000 {
				allZeros := true
				for _, b := range data {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Logf("Generated all-zero random data of length %d (rare but possible)", length)
				}
			}
		}
		
		// Invalid lengths should always fail
		if length <= 0 && err == nil {
			t.Error("GenerateRandomBytes should fail with non-positive length")
		}
		
		if length > MaxTokenLength && err == nil {
			t.Error("GenerateRandomBytes should fail with length exceeding maximum")
		}
	})
}

// FuzzGenerateSecureToken tests token generation with various parameters
func FuzzGenerateSecureToken(f *testing.F) {
	// Seed with various token configurations
	f.Add(int(32), int(TokenFormatHex))
	f.Add(int(16), int(TokenFormatBase64))
	f.Add(int(24), int(TokenFormatBase64URL))
	f.Add(int(20), int(TokenFormatAlphanumeric))
	f.Add(int(0), int(TokenFormatHex))
	f.Add(int(-1), int(TokenFormatHex))
	f.Add(int(1000), int(TokenFormatHex))
	f.Add(int(32), int(999)) // Invalid format
	
	f.Fuzz(func(t *testing.T, length int, formatInt int) {
		// Limit length to prevent resource exhaustion
		if length > 10000 {
			length = 10000
		}
		
		format := TokenFormat(formatInt)
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GenerateSecureToken panicked with length=%d, format=%d", length, formatInt)
			}
		}()
		
		token, err := GenerateSecureToken(length, format)
		
		if err == nil {
			if len(token) != length {
				t.Errorf("Token length mismatch: got %d, expected %d", len(token), length)
			}
			
			// Validate token format if it succeeded
			if validateErr := ValidateTokenFormat(token, length, format); validateErr != nil {
				t.Errorf("Generated token failed format validation: %v", validateErr)
			}
		}
		
		// Invalid lengths should always fail
		if length < MinTokenLength && err == nil {
			t.Error("GenerateSecureToken should fail with length below minimum")
		}
		
		if length > MaxTokenLength && err == nil {
			t.Error("GenerateSecureToken should fail with length exceeding maximum")
		}
		
		// Invalid formats should always fail
		validFormats := []TokenFormat{TokenFormatHex, TokenFormatBase64, TokenFormatBase64URL, TokenFormatAlphanumeric}
		isValidFormat := false
		for _, validFormat := range validFormats {
			if format == validFormat {
				isValidFormat = true
				break
			}
		}
		if !isValidFormat && err == nil {
			t.Error("GenerateSecureToken should fail with invalid format")
		}
	})
}

// FuzzValidateTokenFormat tests token format validation with various inputs
func FuzzValidateTokenFormat(f *testing.F) {
	// Seed with various token examples
	f.Add("deadbeef123456789abcdef0", int(24), int(TokenFormatHex))
	f.Add("ABC123def456GHI789jkl012", int(24), int(TokenFormatAlphanumeric))
	f.Add("ABCDEFGHIJKLMNOPabcdef01", int(24), int(TokenFormatBase64URL))
	f.Add("invalid!@#token", int(14), int(TokenFormatHex))
	f.Add("", int(0), int(TokenFormatHex))
	
	f.Fuzz(func(t *testing.T, token string, expectedLength int, formatInt int) {
		// Limit token length to prevent resource exhaustion
		if len(token) > 10000 {
			token = token[:10000]
		}
		
		format := TokenFormat(formatInt)
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateTokenFormat panicked with token=%q, length=%d, format=%d", 
					token, expectedLength, formatInt)
			}
		}()
		
		err := ValidateTokenFormat(token, expectedLength, format)
		
		// Length mismatch should always fail
		if len(token) != expectedLength && err == nil {
			t.Error("ValidateTokenFormat should fail with length mismatch")
		}
		
		// If validation succeeds, the token should indeed be valid for the format
		if err == nil {
			switch format {
			case TokenFormatHex:
				for _, char := range token {
					if !isHexChar(char) {
						t.Errorf("Token validated as hex but contains invalid char: %c", char)
					}
				}
			case TokenFormatAlphanumeric:
				for _, char := range token {
					if !isAlphanumericChar(char) {
						t.Errorf("Token validated as alphanumeric but contains invalid char: %c", char)
					}
				}
			case TokenFormatBase64URL:
				for _, char := range token {
					if !isBase64URLChar(char) {
						t.Errorf("Token validated as base64url but contains invalid char: %c", char)
					}
				}
			}
		}
	})
}

// FuzzEncryptDecryptDataKey tests data key encryption/decryption with various inputs
func FuzzEncryptDecryptDataKey(f *testing.F) {
	// Generate valid keys for testing
	validMasterKey, _ := GenerateDataKey()
	validDataKey, _ := GenerateDataKey()
	
	// Seed with various key combinations
	f.Add(validMasterKey, validDataKey, uint32(1))
	f.Add([]byte("short"), validDataKey, uint32(1))
	f.Add(validMasterKey, []byte("short"), uint32(1))
	f.Add(validMasterKey, validDataKey, uint32(0))
	f.Add(validMasterKey, validDataKey, uint32(999))
	
	f.Fuzz(func(t *testing.T, masterKey []byte, dataKey []byte, version uint32) {
		// Limit key sizes
		if len(masterKey) > 1000 {
			masterKey = masterKey[:1000]
		}
		if len(dataKey) > 1000 {
			dataKey = dataKey[:1000]
		}
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("EncryptDataKey/DecryptDataKey panicked with masterKey len=%d, dataKey len=%d, version=%d", 
					len(masterKey), len(dataKey), version)
			}
		}()
		
		encryptedDataKey, encErr := EncryptDataKey(masterKey, dataKey)
		
		if encErr == nil {
			// If encryption succeeds, decryption should work
			decryptedDataKey, decErr := DecryptDataKey(masterKey, encryptedDataKey, CurrentEncryptionVersion)
			if decErr != nil {
				t.Errorf("Failed to decrypt successfully encrypted data key: %v", decErr)
			} else if !bytes.Equal(dataKey, decryptedDataKey) {
				t.Errorf("Decrypted data key doesn't match original")
			}
			
			// Try decrypting with wrong version
			_, wrongVersionErr := DecryptDataKey(masterKey, encryptedDataKey, version)
			if version != CurrentEncryptionVersion && wrongVersionErr == nil {
				t.Error("DecryptDataKey should fail with wrong version")
			}
		}
		
		// Wrong key sizes should always fail
		if len(masterKey) != AESKeySize && encErr == nil {
			t.Error("EncryptDataKey should fail with wrong master key size")
		}
		
		if len(dataKey) != AESKeySize && encErr == nil {
			t.Error("EncryptDataKey should fail with wrong data key size")
		}
	})
}