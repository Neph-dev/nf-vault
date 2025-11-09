package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDFParams holds the configuration parameters for Argon2id key derivation.
// These parameters control the computational cost and security of key derivation.
type KDFParams struct {
	// Time represents the number of iterations (time cost)
	// Recommended minimum: 1, typical production: 3-4
	Time uint32
	
	// Memory represents the memory usage in KiB (memory cost)
	// Recommended minimum: 64MB (65536 KiB), typical production: 256MB (262144 KiB)
	Memory uint32
	
	// Threads represents the number of parallel threads
	// Should match the number of CPU cores, typical: 4
	Threads uint8
	
	// KeyLen represents the desired output key length in bytes
	// For AES-256: 32 bytes
	KeyLen uint32
	
	// SaltLen represents the salt length in bytes
	// Recommended minimum: 16 bytes, typical: 32 bytes
	SaltLen uint32
}

// DefaultKDFParams returns secure default parameters for Argon2id.
// These parameters provide a good balance between security and performance
// for typical desktop/server environments.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Time:    3,        // 3 iterations
		Memory:  262144,   // 256 MB
		Threads: 4,        // 4 parallel threads
		KeyLen:  32,       // 32 bytes for AES-256
		SaltLen: 32,       // 32 byte salt
	}
}

// FastKDFParams returns faster parameters suitable for testing or
// low-security environments. DO NOT use in production.
func FastKDFParams() KDFParams {
	return KDFParams{
		Time:    1,        // 1 iteration
		Memory:  65536,    // 64 MB
		Threads: 1,        // 1 thread
		KeyLen:  32,       // 32 bytes for AES-256
		SaltLen: 16,       // 16 byte salt
	}
}

// ValidateKDFParams validates the KDF parameters according to security best practices.
// Returns an error if any parameter is below the recommended minimum.
func ValidateKDFParams(params KDFParams) error {
	if params.Time < 1 {
		return errors.New("time parameter must be at least 1")
	}
	
	if params.Memory < 65536 { // 64 MB minimum
		return errors.New("memory parameter must be at least 65536 KiB (64 MB)")
	}
	
	if params.Threads < 1 {
		return errors.New("threads parameter must be at least 1")
	}
	
	if params.KeyLen < 16 {
		return errors.New("key length must be at least 16 bytes")
	}
	
	if params.SaltLen < 16 {
		return errors.New("salt length must be at least 16 bytes")
	}
	
	return nil
}

// GenerateSalt generates a cryptographically secure random salt
// of the specified length.
func GenerateSalt(length uint32) ([]byte, error) {
	if length == 0 {
		return nil, errors.New("salt length must be greater than 0")
	}
	
	salt := make([]byte, length)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	if n != int(length) {
		return nil, fmt.Errorf("failed to generate full salt: got %d bytes, expected %d", n, length)
	}
	
	return salt, nil
}

// DeriveKey derives a key from a passphrase using Argon2id with the given parameters.
// The function is deterministic: the same passphrase and salt will always produce
// the same key.
//
// Parameters:
//   - passphrase: the user's passphrase (will be cleared from memory after use)
//   - salt: cryptographically random salt
//   - params: Argon2id parameters
//
// Returns:
//   - derived key of params.KeyLen bytes
//   - error if derivation fails
func DeriveKey(passphrase []byte, salt []byte, params KDFParams) ([]byte, error) {
	// Validate inputs
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase cannot be empty")
	}
	
	if len(salt) != int(params.SaltLen) {
		return nil, fmt.Errorf("salt length mismatch: got %d, expected %d", 
			len(salt), params.SaltLen)
	}
	
	if err := ValidateKDFParams(params); err != nil {
		return nil, fmt.Errorf("invalid KDF parameters: %w", err)
	}
	
	// Derive key using Argon2id
	// Argon2id combines Argon2i (data-independent) and Argon2d (data-dependent)
	// providing resistance against both side-channel and GPU attacks
	key := argon2.IDKey(
		passphrase,
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)
	
	// Verify that we got the expected key length
	if len(key) != int(params.KeyLen) {
		return nil, fmt.Errorf("unexpected key length: got %d, expected %d", 
			len(key), params.KeyLen)
	}
	
	return key, nil
}

// DeriveKeyWithNewSalt is a convenience function that generates a new salt
// and derives a key in one call. Returns both the derived key and the salt
// that was used (which must be stored for later verification).
func DeriveKeyWithNewSalt(passphrase []byte, params KDFParams) (key []byte, salt []byte, err error) {
	salt, err = GenerateSalt(params.SaltLen)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	key, err = DeriveKey(passphrase, salt, params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	
	return key, salt, nil
}

// SecureZero overwrites the byte slice with zeros to clear sensitive data from memory.
// This provides a best-effort attempt to clear sensitive data, though it cannot
// guarantee that all copies in memory are cleared due to GC behavior.
func SecureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}