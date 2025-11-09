package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestConstants(t *testing.T) {
	// Verify cryptographic constants
	if AESKeySize != 32 {
		t.Errorf("AESKeySize should be 32, got %d", AESKeySize)
	}
	
	if AESGCMNonceSize != 12 {
		t.Errorf("AESGCMNonceSize should be 12, got %d", AESGCMNonceSize)
	}
	
	if AESGCMTagSize != 16 {
		t.Errorf("AESGCMTagSize should be 16, got %d", AESGCMTagSize)
	}
	
	expectedEncryptedDataKeySize := AESKeySize + AESGCMNonceSize + AESGCMTagSize
	if EncryptedDataKeySize != expectedEncryptedDataKeySize {
		t.Errorf("EncryptedDataKeySize should be %d, got %d", expectedEncryptedDataKeySize, EncryptedDataKeySize)
	}
}

func TestGenerateDataKey(t *testing.T) {
	key1, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey() failed: %v", err)
	}
	
	if len(key1) != AESKeySize {
		t.Errorf("Generated key has wrong size: got %d, expected %d", len(key1), AESKeySize)
	}
	
	// Generate another key and verify they're different
	key2, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Second GenerateDataKey() failed: %v", err)
	}
	
	if bytes.Equal(key1, key2) {
		t.Error("Generated keys are identical - not random")
	}
	
	// Verify key is not all zeros
	allZeros := true
	for _, b := range key1 {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Generated key is all zeros")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() failed: %v", err)
	}
	
	if len(nonce1) != AESGCMNonceSize {
		t.Errorf("Generated nonce has wrong size: got %d, expected %d", len(nonce1), AESGCMNonceSize)
	}
	
	// Generate another nonce and verify they're different
	nonce2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("Second GenerateNonce() failed: %v", err)
	}
	
	if bytes.Equal(nonce1, nonce2) {
		t.Error("Generated nonces are identical - not random")
	}
}

func TestEncryptDecryptAESGCM(t *testing.T) {
	key, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	plaintext := []byte("Hello, this is a test message for AES-GCM encryption!")
	additionalData := []byte("additional authenticated data")
	
	// Test encryption
	encrypted, err := encryptAESGCM(key, plaintext, additionalData)
	if err != nil {
		t.Fatalf("encryptAESGCM() failed: %v", err)
	}
	
	expectedMinSize := AESGCMNonceSize + len(plaintext) + AESGCMTagSize
	if len(encrypted) != expectedMinSize {
		t.Errorf("Encrypted data size mismatch: got %d, expected %d", len(encrypted), expectedMinSize)
	}
	
	// Test decryption
	decrypted, err := decryptAESGCM(key, encrypted, additionalData)
	if err != nil {
		t.Fatalf("decryptAESGCM() failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data doesn't match original:\nOriginal: %s\nDecrypted: %s", plaintext, decrypted)
	}
}

func TestEncryptDecryptAESGCMErrors(t *testing.T) {
	key, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	plaintext := []byte("test message")
	additionalData := []byte("test aad")
	
	// Test encryption with wrong key size
	shortKey := key[:16] // AES-128 key
	_, err = encryptAESGCM(shortKey, plaintext, additionalData)
	if err == nil {
		t.Error("encryptAESGCM() should fail with wrong key size")
	}
	
	// Test decryption with wrong key size
	encrypted, err := encryptAESGCM(key, plaintext, additionalData)
	if err != nil {
		t.Fatalf("encryptAESGCM() failed: %v", err)
	}
	
	_, err = decryptAESGCM(shortKey, encrypted, additionalData)
	if err == nil {
		t.Error("decryptAESGCM() should fail with wrong key size")
	}
	
	// Test decryption with too short data
	shortData := encrypted[:5]
	_, err = decryptAESGCM(key, shortData, additionalData)
	if err == nil {
		t.Error("decryptAESGCM() should fail with too short data")
	}
	
	// Test decryption with tampered data
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 1 // Flip one bit in the tag
	
	_, err = decryptAESGCM(key, tampered, additionalData)
	if err == nil {
		t.Error("decryptAESGCM() should fail with tampered data")
	}
	
	// Test decryption with wrong additional data
	wrongAAD := []byte("wrong additional data")
	_, err = decryptAESGCM(key, encrypted, wrongAAD)
	if err == nil {
		t.Error("decryptAESGCM() should fail with wrong additional data")
	}
}

func TestEncryptDecryptDataKey(t *testing.T) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	
	dataKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate data key: %v", err)
	}
	
	// Test encryption
	encryptedDataKey, err := EncryptDataKey(masterKey, dataKey)
	if err != nil {
		t.Fatalf("EncryptDataKey() failed: %v", err)
	}
	
	if len(encryptedDataKey) != EncryptedDataKeySize {
		t.Errorf("Encrypted data key size mismatch: got %d, expected %d", 
			len(encryptedDataKey), EncryptedDataKeySize)
	}
	
	// Test decryption
	decryptedDataKey, err := DecryptDataKey(masterKey, encryptedDataKey, CurrentEncryptionVersion)
	if err != nil {
		t.Fatalf("DecryptDataKey() failed: %v", err)
	}
	
	if !bytes.Equal(dataKey, decryptedDataKey) {
		t.Error("Decrypted data key doesn't match original")
	}
}

func TestEncryptDecryptDataKeyErrors(t *testing.T) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	
	dataKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate data key: %v", err)
	}
	
	// Test encryption with wrong master key size
	shortKey := masterKey[:16]
	_, err = EncryptDataKey(shortKey, dataKey)
	if err == nil {
		t.Error("EncryptDataKey() should fail with wrong master key size")
	}
	
	// Test encryption with wrong data key size
	shortDataKey := dataKey[:16]
	_, err = EncryptDataKey(masterKey, shortDataKey)
	if err == nil {
		t.Error("EncryptDataKey() should fail with wrong data key size")
	}
	
	// Test decryption with wrong master key size
	encryptedDataKey, err := EncryptDataKey(masterKey, dataKey)
	if err != nil {
		t.Fatalf("EncryptDataKey() failed: %v", err)
	}
	
	_, err = DecryptDataKey(shortKey, encryptedDataKey, CurrentEncryptionVersion)
	if err == nil {
		t.Error("DecryptDataKey() should fail with wrong master key size")
	}
	
	// Test decryption with wrong encrypted data key size
	shortEncrypted := encryptedDataKey[:30]
	_, err = DecryptDataKey(masterKey, shortEncrypted, CurrentEncryptionVersion)
	if err == nil {
		t.Error("DecryptDataKey() should fail with wrong encrypted data key size")
	}
}

func TestEncryptDecryptSecret(t *testing.T) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	
	secretData := []byte("This is a very important secret that must be protected!")
	
	// Test encryption
	encrypted, err := EncryptSecret(masterKey, secretData)
	if err != nil {
		t.Fatalf("EncryptSecret() failed: %v", err)
	}
	
	// Validate the encrypted secret structure
	if err := ValidateEncryptedSecret(encrypted); err != nil {
		t.Fatalf("Invalid encrypted secret: %v", err)
	}
	
	if encrypted.Version != CurrentEncryptionVersion {
		t.Errorf("Wrong version: got %d, expected %d", encrypted.Version, CurrentEncryptionVersion)
	}
	
	// Test decryption
	decrypted, err := DecryptSecret(masterKey, encrypted)
	if err != nil {
		t.Fatalf("DecryptSecret() failed: %v", err)
	}
	
	if !bytes.Equal(secretData, decrypted) {
		t.Errorf("Decrypted secret doesn't match original:\nOriginal: %s\nDecrypted: %s", 
			secretData, decrypted)
	}
}

func TestEncryptDecryptSecretMultiple(t *testing.T) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	
	secrets := [][]byte{
		[]byte("secret1"),
		[]byte("This is a longer secret with more content"),
		[]byte("🔐 Unicode secret with emojis! 🛡️"),
		[]byte(""), // This should fail
	}
	
	var encrypted []*EncryptedSecret
	
	// Encrypt all secrets (except empty one)
	for i, secret := range secrets[:len(secrets)-1] {
		enc, err := EncryptSecret(masterKey, secret)
		if err != nil {
			t.Fatalf("EncryptSecret() failed for secret %d: %v", i, err)
		}
		encrypted = append(encrypted, enc)
	}
	
	// Test encryption of empty secret (should fail)
	_, err = EncryptSecret(masterKey, secrets[len(secrets)-1])
	if err == nil {
		t.Error("EncryptSecret() should fail with empty secret")
	}
	
	// Verify all encrypted secrets have different data keys
	for i := 0; i < len(encrypted); i++ {
		for j := i + 1; j < len(encrypted); j++ {
			if bytes.Equal(encrypted[i].EncryptedDataKey, encrypted[j].EncryptedDataKey) {
				t.Errorf("Secrets %d and %d have the same encrypted data key", i, j)
			}
			if bytes.Equal(encrypted[i].EncryptedData, encrypted[j].EncryptedData) {
				t.Errorf("Secrets %d and %d have the same encrypted data", i, j)
			}
		}
	}
	
	// Decrypt all secrets and verify
	for i, enc := range encrypted {
		decrypted, err := DecryptSecret(masterKey, enc)
		if err != nil {
			t.Fatalf("DecryptSecret() failed for secret %d: %v", i, err)
		}
		
		if !bytes.Equal(secrets[i], decrypted) {
			t.Errorf("Secret %d doesn't match after decryption", i)
		}
	}
}

func TestEncryptDecryptSecretErrors(t *testing.T) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	
	secretData := []byte("test secret")
	
	// Test encryption with wrong master key size
	shortKey := masterKey[:16]
	_, err = EncryptSecret(shortKey, secretData)
	if err == nil {
		t.Error("EncryptSecret() should fail with wrong master key size")
	}
	
	// Test encryption with empty secret
	_, err = EncryptSecret(masterKey, []byte{})
	if err == nil {
		t.Error("EncryptSecret() should fail with empty secret")
	}
	
	// Test decryption with nil encrypted secret
	_, err = DecryptSecret(masterKey, nil)
	if err == nil {
		t.Error("DecryptSecret() should fail with nil encrypted secret")
	}
	
	// Test decryption with wrong master key size
	encrypted, err := EncryptSecret(masterKey, secretData)
	if err != nil {
		t.Fatalf("EncryptSecret() failed: %v", err)
	}
	
	_, err = DecryptSecret(shortKey, encrypted)
	if err == nil {
		t.Error("DecryptSecret() should fail with wrong master key size")
	}
	
	// Test decryption with wrong version
	wrongVersionSecret := &EncryptedSecret{
		EncryptedDataKey: encrypted.EncryptedDataKey,
		EncryptedData:    encrypted.EncryptedData,
		Version:          999, // Wrong version
	}
	
	_, err = DecryptSecret(masterKey, wrongVersionSecret)
	if err == nil {
		t.Error("DecryptSecret() should fail with wrong version")
	}
}

func TestTamperDetection(t *testing.T) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	
	secretData := []byte("tamper detection test")
	
	encrypted, err := EncryptSecret(masterKey, secretData)
	if err != nil {
		t.Fatalf("EncryptSecret() failed: %v", err)
	}
	
	// Test tampering with encrypted data key
	tamperedSecret1 := &EncryptedSecret{
		EncryptedDataKey: make([]byte, len(encrypted.EncryptedDataKey)),
		EncryptedData:    encrypted.EncryptedData,
		Version:          encrypted.Version,
	}
	copy(tamperedSecret1.EncryptedDataKey, encrypted.EncryptedDataKey)
	tamperedSecret1.EncryptedDataKey[0] ^= 1 // Flip one bit
	
	_, err = DecryptSecret(masterKey, tamperedSecret1)
	if err == nil {
		t.Error("DecryptSecret() should fail with tampered encrypted data key")
	}
	
	// Test tampering with encrypted data
	tamperedSecret2 := &EncryptedSecret{
		EncryptedDataKey: encrypted.EncryptedDataKey,
		EncryptedData:    make([]byte, len(encrypted.EncryptedData)),
		Version:          encrypted.Version,
	}
	copy(tamperedSecret2.EncryptedData, encrypted.EncryptedData)
	tamperedSecret2.EncryptedData[len(tamperedSecret2.EncryptedData)-1] ^= 1 // Flip one bit in tag
	
	_, err = DecryptSecret(masterKey, tamperedSecret2)
	if err == nil {
		t.Error("DecryptSecret() should fail with tampered encrypted data")
	}
}

func TestValidateEncryptedSecret(t *testing.T) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	
	secretData := []byte("validation test")
	
	encrypted, err := EncryptSecret(masterKey, secretData)
	if err != nil {
		t.Fatalf("EncryptSecret() failed: %v", err)
	}
	
	// Test valid secret
	if err := ValidateEncryptedSecret(encrypted); err != nil {
		t.Errorf("ValidateEncryptedSecret() failed for valid secret: %v", err)
	}
	
	// Test nil secret
	if err := ValidateEncryptedSecret(nil); err == nil {
		t.Error("ValidateEncryptedSecret() should fail for nil secret")
	}
	
	// Test wrong encrypted data key size
	invalidSecret1 := &EncryptedSecret{
		EncryptedDataKey: []byte("too short"),
		EncryptedData:    encrypted.EncryptedData,
		Version:          encrypted.Version,
	}
	if err := ValidateEncryptedSecret(invalidSecret1); err == nil {
		t.Error("ValidateEncryptedSecret() should fail for wrong encrypted data key size")
	}
	
	// Test too short encrypted data
	invalidSecret2 := &EncryptedSecret{
		EncryptedDataKey: encrypted.EncryptedDataKey,
		EncryptedData:    []byte("short"),
		Version:          encrypted.Version,
	}
	if err := ValidateEncryptedSecret(invalidSecret2); err == nil {
		t.Error("ValidateEncryptedSecret() should fail for too short encrypted data")
	}
	
	// Test zero version
	invalidSecret3 := &EncryptedSecret{
		EncryptedDataKey: encrypted.EncryptedDataKey,
		EncryptedData:    encrypted.EncryptedData,
		Version:          0,
	}
	if err := ValidateEncryptedSecret(invalidSecret3); err == nil {
		t.Error("ValidateEncryptedSecret() should fail for zero version")
	}
}

func TestCryptographicIsolation(t *testing.T) {
	// This test verifies that different secrets are cryptographically isolated
	// even when encrypted with the same master key
	
	masterKey, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}
	
	secret1 := []byte("secret number one")
	secret2 := []byte("secret number two")
	
	encrypted1, err := EncryptSecret(masterKey, secret1)
	if err != nil {
		t.Fatalf("EncryptSecret() failed for secret1: %v", err)
	}
	
	encrypted2, err := EncryptSecret(masterKey, secret2)
	if err != nil {
		t.Fatalf("EncryptSecret() failed for secret2: %v", err)
	}
	
	// Verify different data keys were used
	if bytes.Equal(encrypted1.EncryptedDataKey, encrypted2.EncryptedDataKey) {
		t.Error("Same data key used for different secrets - no cryptographic isolation")
	}
	
	// Verify we can't decrypt secret1 with secret2's data key
	// We can't easily test this directly, but we can verify that swapping
	// encrypted data keys breaks decryption
	swappedSecret := &EncryptedSecret{
		EncryptedDataKey: encrypted2.EncryptedDataKey, // Wrong data key
		EncryptedData:    encrypted1.EncryptedData,    // Original data
		Version:          encrypted1.Version,
	}
	
	_, err = DecryptSecret(masterKey, swappedSecret)
	if err == nil {
		t.Error("Should not be able to decrypt with wrong data key")
	}
}

// Benchmark tests for performance analysis
func BenchmarkEncryptSecret(b *testing.B) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		b.Fatalf("Failed to generate master key: %v", err)
	}
	
	secretData := make([]byte, 1024) // 1KB secret
	rand.Read(secretData)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptSecret(masterKey, secretData)
		if err != nil {
			b.Fatalf("EncryptSecret() failed: %v", err)
		}
	}
}

func BenchmarkDecryptSecret(b *testing.B) {
	masterKey, err := GenerateDataKey()
	if err != nil {
		b.Fatalf("Failed to generate master key: %v", err)
	}
	
	secretData := make([]byte, 1024) // 1KB secret
	rand.Read(secretData)
	
	encrypted, err := EncryptSecret(masterKey, secretData)
	if err != nil {
		b.Fatalf("EncryptSecret() failed: %v", err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptSecret(masterKey, encrypted)
		if err != nil {
			b.Fatalf("DecryptSecret() failed: %v", err)
		}
	}
}