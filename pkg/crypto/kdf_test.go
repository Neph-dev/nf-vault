package crypto

import (
	"bytes"
	"testing"
)

func TestDefaultKDFParams(t *testing.T) {
	params := DefaultKDFParams()
	
	// Verify default parameters meet security requirements
	if params.Time < 1 {
		t.Errorf("Default time parameter too low: %d", params.Time)
	}
	
	if params.Memory < 65536 {
		t.Errorf("Default memory parameter too low: %d", params.Memory)
	}
	
	if params.Threads < 1 {
		t.Errorf("Default threads parameter too low: %d", params.Threads)
	}
	
	if params.KeyLen != 32 {
		t.Errorf("Expected key length 32, got %d", params.KeyLen)
	}
	
	if params.SaltLen < 16 {
		t.Errorf("Default salt length too short: %d", params.SaltLen)
	}
}

func TestValidateKDFParams(t *testing.T) {
	tests := []struct {
		name    string
		params  KDFParams
		wantErr bool
	}{
		{
			name:    "valid default params",
			params:  DefaultKDFParams(),
			wantErr: false,
		},
		{
			name: "zero time",
			params: KDFParams{
				Time:    0,
				Memory:  65536,
				Threads: 1,
				KeyLen:  32,
				SaltLen: 16,
			},
			wantErr: true,
		},
		{
			name: "low memory",
			params: KDFParams{
				Time:    1,
				Memory:  1024, // Too low
				Threads: 1,
				KeyLen:  32,
				SaltLen: 16,
			},
			wantErr: true,
		},
		{
			name: "zero threads",
			params: KDFParams{
				Time:    1,
				Memory:  65536,
				Threads: 0,
				KeyLen:  32,
				SaltLen: 16,
			},
			wantErr: true,
		},
		{
			name: "short key length",
			params: KDFParams{
				Time:    1,
				Memory:  65536,
				Threads: 1,
				KeyLen:  8, // Too short
				SaltLen: 16,
			},
			wantErr: true,
		},
		{
			name: "short salt length",
			params: KDFParams{
				Time:    1,
				Memory:  65536,
				Threads: 1,
				KeyLen:  32,
				SaltLen: 8, // Too short
			},
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKDFParams(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKDFParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateSalt(t *testing.T) {
	tests := []struct {
		name    string
		length  uint32
		wantErr bool
	}{
		{
			name:    "valid 16 byte salt",
			length:  16,
			wantErr: false,
		},
		{
			name:    "valid 32 byte salt",
			length:  32,
			wantErr: false,
		},
		{
			name:    "zero length",
			length:  0,
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt, err := GenerateSalt(tt.length)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSalt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if len(salt) != int(tt.length) {
					t.Errorf("GenerateSalt() returned salt of length %d, expected %d", len(salt), tt.length)
				}
				
				// Test that salt is not all zeros (extremely unlikely for random data)
				allZeros := true
				for _, b := range salt {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Error("GenerateSalt() returned all zeros - likely not random")
				}
			}
		})
	}
}

func TestGenerateSaltUniqueness(t *testing.T) {
	// Generate multiple salts and verify they are different
	const numSalts = 100
	const saltLength = 32
	
	salts := make([][]byte, numSalts)
	for i := 0; i < numSalts; i++ {
		salt, err := GenerateSalt(saltLength)
		if err != nil {
			t.Fatalf("GenerateSalt() failed: %v", err)
		}
		salts[i] = salt
	}
	
	// Check for duplicates
	for i := 0; i < numSalts; i++ {
		for j := i + 1; j < numSalts; j++ {
			if bytes.Equal(salts[i], salts[j]) {
				t.Errorf("Generated duplicate salts at indices %d and %d", i, j)
			}
		}
	}
}

func TestDeriveKey(t *testing.T) {
	passphrase := []byte("test-passphrase-123")
	params := FastKDFParams() // Use fast params for testing
	
	salt, err := GenerateSalt(params.SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	
	key, err := DeriveKey(passphrase, salt, params)
	if err != nil {
		t.Fatalf("DeriveKey() failed: %v", err)
	}
	
	if len(key) != int(params.KeyLen) {
		t.Errorf("Key length mismatch: got %d, expected %d", len(key), params.KeyLen)
	}
	
	// Test that key is not all zeros
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Derived key is all zeros")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	passphrase := []byte("deterministic-test-passphrase")
	params := FastKDFParams()
	
	salt, err := GenerateSalt(params.SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	
	// Derive the same key multiple times
	key1, err := DeriveKey(passphrase, salt, params)
	if err != nil {
		t.Fatalf("First DeriveKey() failed: %v", err)
	}
	
	key2, err := DeriveKey(passphrase, salt, params)
	if err != nil {
		t.Fatalf("Second DeriveKey() failed: %v", err)
	}
	
	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey() is not deterministic - same inputs produced different outputs")
	}
}

func TestDeriveKeyDifferentInputs(t *testing.T) {
	params := FastKDFParams()
	
	// Test different passphrases produce different keys
	salt, err := GenerateSalt(params.SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	
	key1, err := DeriveKey([]byte("passphrase1"), salt, params)
	if err != nil {
		t.Fatalf("First DeriveKey() failed: %v", err)
	}
	
	key2, err := DeriveKey([]byte("passphrase2"), salt, params)
	if err != nil {
		t.Fatalf("Second DeriveKey() failed: %v", err)
	}
	
	if bytes.Equal(key1, key2) {
		t.Error("Different passphrases produced the same key")
	}
	
	// Test different salts produce different keys
	passphrase := []byte("same-passphrase")
	
	salt1, err := GenerateSalt(params.SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate salt1: %v", err)
	}
	
	salt2, err := GenerateSalt(params.SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate salt2: %v", err)
	}
	
	key3, err := DeriveKey(passphrase, salt1, params)
	if err != nil {
		t.Fatalf("Third DeriveKey() failed: %v", err)
	}
	
	key4, err := DeriveKey(passphrase, salt2, params)
	if err != nil {
		t.Fatalf("Fourth DeriveKey() failed: %v", err)
	}
	
	if bytes.Equal(key3, key4) {
		t.Error("Different salts produced the same key")
	}
}

func TestDeriveKeyErrors(t *testing.T) {
	params := FastKDFParams()
	
	salt, err := GenerateSalt(params.SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	
	tests := []struct {
		name       string
		passphrase []byte
		salt       []byte
		params     KDFParams
		wantErr    bool
	}{
		{
			name:       "empty passphrase",
			passphrase: []byte{},
			salt:       salt,
			params:     params,
			wantErr:    true,
		},
		{
			name:       "nil passphrase",
			passphrase: nil,
			salt:       salt,
			params:     params,
			wantErr:    true,
		},
		{
			name:       "wrong salt length",
			passphrase: []byte("test"),
			salt:       []byte("short"),
			params:     params,
			wantErr:    true,
		},
		{
			name:       "invalid params",
			passphrase: []byte("test"),
			salt:       salt,
			params: KDFParams{
				Time:    0, // Invalid
				Memory:  params.Memory,
				Threads: params.Threads,
				KeyLen:  params.KeyLen,
				SaltLen: params.SaltLen,
			},
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveKey(tt.passphrase, tt.salt, tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeriveKeyWithNewSalt(t *testing.T) {
	passphrase := []byte("test-passphrase")
	params := FastKDFParams()
	
	key, salt, err := DeriveKeyWithNewSalt(passphrase, params)
	if err != nil {
		t.Fatalf("DeriveKeyWithNewSalt() failed: %v", err)
	}
	
	if len(key) != int(params.KeyLen) {
		t.Errorf("Key length mismatch: got %d, expected %d", len(key), params.KeyLen)
	}
	
	if len(salt) != int(params.SaltLen) {
		t.Errorf("Salt length mismatch: got %d, expected %d", len(salt), params.SaltLen)
	}
	
	// Verify we can derive the same key using the returned salt
	key2, err := DeriveKey(passphrase, salt, params)
	if err != nil {
		t.Fatalf("Failed to re-derive key: %v", err)
	}
	
	if !bytes.Equal(key, key2) {
		t.Error("Re-derived key doesn't match original")
	}
}

func TestSecureZero(t *testing.T) {
	data := []byte("sensitive data that should be cleared")
	original := make([]byte, len(data))
	copy(original, data)
	
	SecureZero(data)
	
	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d was not zeroed: %d", i, b)
		}
	}
	
	// Verify original data was different (sanity check)
	allZeros := true
	for _, b := range original {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Original data was already all zeros - test invalid")
	}
}

// Benchmark tests for performance analysis
func BenchmarkDeriveKey(b *testing.B) {
	passphrase := []byte("benchmark-passphrase")
	params := DefaultKDFParams()
	
	salt, err := GenerateSalt(params.SaltLen)
	if err != nil {
		b.Fatalf("Failed to generate salt: %v", err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DeriveKey(passphrase, salt, params)
		if err != nil {
			b.Fatalf("DeriveKey() failed: %v", err)
		}
	}
}

func BenchmarkGenerateSalt(b *testing.B) {
	const saltLength = 32
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateSalt(saltLength)
		if err != nil {
			b.Fatalf("GenerateSalt() failed: %v", err)
		}
	}
}