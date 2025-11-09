package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// AESKeySize is the required key size for AES-256 (32 bytes)
	AESKeySize = 32
	
	// AESGCMNonceSize is the required nonce size for AES-GCM (12 bytes)
	AESGCMNonceSize = 12
	
	// AESGCMTagSize is the authentication tag size for AES-GCM (16 bytes)
	AESGCMTagSize = 16
	
	// EncryptedDataKeySize is the size of encrypted data keys
	// This includes the encrypted DEK (32 bytes) + nonce (12 bytes) + tag (16 bytes)
	EncryptedDataKeySize = AESKeySize + AESGCMNonceSize + AESGCMTagSize
)

// EncryptedSecret represents an encrypted secret with its metadata.
// This structure implements the KEK (Key Encryption Key) pattern where:
// - Master key (KEK) encrypts per-secret data keys (DEK)
// - Data keys encrypt the actual secret data
// - Each secret has its own unique data key for cryptographic isolation
type EncryptedSecret struct {
	// EncryptedDataKey contains the AES-256 key encrypted with the master key
	// Format: [nonce(12) || encrypted_key(32) || tag(16)] = 60 bytes total
	EncryptedDataKey []byte
	
	// EncryptedData contains the secret data encrypted with the data key
	// Format: [nonce(12) || encrypted_data(variable) || tag(16)]
	EncryptedData []byte
	
	// Version indicates the encryption format version for future compatibility
	Version uint32
}

// CurrentEncryptionVersion is the current version of the encryption format
const CurrentEncryptionVersion uint32 = 1

// GenerateDataKey creates a new random 256-bit AES key for encrypting secret data.
// Each secret should have its own unique data key.
func GenerateDataKey() ([]byte, error) {
	key := make([]byte, AESKeySize)
	n, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	
	if n != AESKeySize {
		return nil, fmt.Errorf("failed to generate full data key: got %d bytes, expected %d", n, AESKeySize)
	}
	
	return key, nil
}

// GenerateNonce creates a new random nonce for AES-GCM encryption.
// Each encryption operation must use a unique nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, AESGCMNonceSize)
	n, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	if n != AESGCMNonceSize {
		return nil, fmt.Errorf("failed to generate full nonce: got %d bytes, expected %d", n, AESGCMNonceSize)
	}
	
	return nonce, nil
}

// encryptAESGCM performs AES-GCM encryption with the given key, plaintext, and additional data.
// Returns: [nonce || ciphertext || tag]
func encryptAESGCM(key, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, fmt.Errorf("invalid key size: got %d, expected %d", len(key), AESKeySize)
	}
	
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	
	// Generate nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
	
	// Return: nonce || ciphertext (includes tag)
	result := make([]byte, 0, len(nonce)+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	
	return result, nil
}

// decryptAESGCM performs AES-GCM decryption with the given key and ciphertext.
// Expects input format: [nonce || ciphertext || tag]
func decryptAESGCM(key, encryptedData, additionalData []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, fmt.Errorf("invalid key size: got %d, expected %d", len(key), AESKeySize)
	}
	
	if len(encryptedData) < AESGCMNonceSize+AESGCMTagSize {
		return nil, fmt.Errorf("encrypted data too short: got %d, minimum %d", 
			len(encryptedData), AESGCMNonceSize+AESGCMTagSize)
	}
	
	// Extract nonce and ciphertext
	nonce := encryptedData[:AESGCMNonceSize]
	ciphertext := encryptedData[AESGCMNonceSize:]
	
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	
	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	return plaintext, nil
}

// EncryptDataKey encrypts a data encryption key (DEK) using the master key (KEK).
// Returns the encrypted data key in the format: [nonce || encrypted_key || tag]
func EncryptDataKey(masterKey, dataKey []byte) ([]byte, error) {
	if len(masterKey) != AESKeySize {
		return nil, fmt.Errorf("invalid master key size: got %d, expected %d", len(masterKey), AESKeySize)
	}
	
	if len(dataKey) != AESKeySize {
		return nil, fmt.Errorf("invalid data key size: got %d, expected %d", len(dataKey), AESKeySize)
	}
	
	// Use version as additional authenticated data
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, CurrentEncryptionVersion)
	
	return encryptAESGCM(masterKey, dataKey, versionBytes)
}

// DecryptDataKey decrypts a data encryption key (DEK) using the master key (KEK).
// Expects encrypted data in the format: [nonce || encrypted_key || tag]
func DecryptDataKey(masterKey, encryptedDataKey []byte, version uint32) ([]byte, error) {
	if len(masterKey) != AESKeySize {
		return nil, fmt.Errorf("invalid master key size: got %d, expected %d", len(masterKey), AESKeySize)
	}
	
	if len(encryptedDataKey) != EncryptedDataKeySize {
		return nil, fmt.Errorf("invalid encrypted data key size: got %d, expected %d", 
			len(encryptedDataKey), EncryptedDataKeySize)
	}
	
	// Use version as additional authenticated data
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, version)
	
	dataKey, err := decryptAESGCM(masterKey, encryptedDataKey, versionBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}
	
	if len(dataKey) != AESKeySize {
		return nil, fmt.Errorf("decrypted data key has invalid size: got %d, expected %d", 
			len(dataKey), AESKeySize)
	}
	
	return dataKey, nil
}

// EncryptSecret encrypts secret data using a new randomly generated data key,
// then encrypts the data key with the master key (KEK pattern).
// Returns an EncryptedSecret containing both the encrypted data and encrypted data key.
func EncryptSecret(masterKey, secretData []byte) (*EncryptedSecret, error) {
	if len(masterKey) != AESKeySize {
		return nil, fmt.Errorf("invalid master key size: got %d, expected %d", len(masterKey), AESKeySize)
	}
	
	if len(secretData) == 0 {
		return nil, errors.New("secret data cannot be empty")
	}
	
	// Generate a new data key for this secret
	dataKey, err := GenerateDataKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	
	// Ensure data key is cleared from memory after use
	defer SecureZero(dataKey)
	
	// Encrypt the data key with the master key
	encryptedDataKey, err := EncryptDataKey(masterKey, dataKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data key: %w", err)
	}
	
	// Use version as additional authenticated data for the secret
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, CurrentEncryptionVersion)
	
	// Encrypt the secret data with the data key
	encryptedData, err := encryptAESGCM(dataKey, secretData, versionBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret data: %w", err)
	}
	
	return &EncryptedSecret{
		EncryptedDataKey: encryptedDataKey,
		EncryptedData:    encryptedData,
		Version:          CurrentEncryptionVersion,
	}, nil
}

// DecryptSecret decrypts an encrypted secret by first decrypting the data key
// with the master key, then using the data key to decrypt the secret data.
func DecryptSecret(masterKey []byte, encrypted *EncryptedSecret) ([]byte, error) {
	if len(masterKey) != AESKeySize {
		return nil, fmt.Errorf("invalid master key size: got %d, expected %d", len(masterKey), AESKeySize)
	}
	
	if encrypted == nil {
		return nil, errors.New("encrypted secret cannot be nil")
	}
	
	// Validate version
	if encrypted.Version != CurrentEncryptionVersion {
		return nil, fmt.Errorf("unsupported encryption version: %d", encrypted.Version)
	}
	
	// Decrypt the data key
	dataKey, err := DecryptDataKey(masterKey, encrypted.EncryptedDataKey, encrypted.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}
	
	// Ensure data key is cleared from memory after use
	defer SecureZero(dataKey)
	
	// Use version as additional authenticated data
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, encrypted.Version)
	
	// Decrypt the secret data
	secretData, err := decryptAESGCM(dataKey, encrypted.EncryptedData, versionBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret data: %w", err)
	}
	
	return secretData, nil
}

// ValidateEncryptedSecret performs basic validation on an EncryptedSecret structure.
func ValidateEncryptedSecret(encrypted *EncryptedSecret) error {
	if encrypted == nil {
		return errors.New("encrypted secret cannot be nil")
	}
	
	if len(encrypted.EncryptedDataKey) != EncryptedDataKeySize {
		return fmt.Errorf("invalid encrypted data key size: got %d, expected %d", 
			len(encrypted.EncryptedDataKey), EncryptedDataKeySize)
	}
	
	if len(encrypted.EncryptedData) < AESGCMNonceSize+AESGCMTagSize {
		return fmt.Errorf("encrypted data too short: got %d, minimum %d", 
			len(encrypted.EncryptedData), AESGCMNonceSize+AESGCMTagSize)
	}
	
	if encrypted.Version == 0 {
		return errors.New("version cannot be zero")
	}
	
	return nil
}