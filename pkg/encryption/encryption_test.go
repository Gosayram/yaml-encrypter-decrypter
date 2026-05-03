package encryption

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
)

func decodeCipherForTest(t *testing.T, ciphertext string) ([]byte, *CipherMetadata) {
	t.Helper()

	base64Payload, envelopeMeta, err := parseVisibleCipherEnvelope(ciphertext)
	if err != nil {
		t.Fatalf("parseVisibleCipherEnvelope() error = %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(base64Payload)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}

	return raw, envelopeMeta
}

func encodeCipherForTest(raw []byte, envelopeMeta *CipherMetadata) string {
	payload := base64.StdEncoding.EncodeToString(raw)
	if envelopeMeta == nil {
		return payload
	}
	return buildVisibleCipherEnvelope(payload, envelopeMeta.Algorithm, envelopeMeta.CreatedAt)
}

func TestEncryptDecrypt(t *testing.T) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting TestEncryptDecrypt")

	tests := []struct {
		name          string
		key           string
		data          string
		errorEncrypt  bool
		errorDecrypt  bool
		errorContains string
	}{
		{
			name: "valid data",
			key:  "P@ssw0rd_Str0ng!T3st#2024",
			data: "This is a test string.",
		},
		{
			name:         "empty data",
			key:          "P@ssw0rd_Str0ng!T3st#2024",
			data:         "",
			errorEncrypt: true, // expecting error with empty data
		},
		{
			name: "longer data",
			key:  "P@ssw0rd_Str0ng!T3st#2024",
			data: "This is a longer test string that spans multiple lines.\nIt contains line breaks and special characters: !@#$%^&*()",
		},
		{
			name:          "empty key",
			key:           "",
			data:          "This is a test string.",
			errorEncrypt:  true,
			errorContains: "password must be at least 15 characters long",
		},
		{
			name:          "too short key",
			key:           "short",
			data:          "This is a test string.",
			errorEncrypt:  true,
			errorContains: "password must be at least 15 characters long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.key, tt.data)
			if (err != nil) != tt.errorEncrypt {
				t.Errorf("Encrypt() error = %v, wantError %v", err, tt.errorEncrypt)
				return
			}
			if tt.errorEncrypt {
				return
			}

			decryptedBuffer, err := Decrypt(tt.key, encrypted)
			if (err != nil) != tt.errorDecrypt {
				t.Errorf("Decrypt() error = %v", err)
				return
			}
			if tt.errorDecrypt {
				return
			}

			if decryptedBuffer != tt.data {
				t.Errorf("Decrypt() = %v, want %v", decryptedBuffer, tt.data)
			}
		})
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	// This test verifies that decryption fails properly when using incorrect passwords
	// We test both valid but incorrect passwords and completely invalid passwords
	tests := []struct {
		name          string
		encryptKey    string
		decryptKey    string
		data          string
		expectError   bool
		errorContains string
	}{
		{
			name:          "completely different password",
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "S9f&h27!Gp*3K5^LmZ#qR8@tUv", // Use a valid but wrong password
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "cipher: message authentication failed",
		},
		{
			name:          "similar password",
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "P@ssw0rd_Str0ng!T3st#2025", // Just one character different
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "cipher: message authentication failed",
		},
		{
			name:          "empty password",
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "Password does not meet strength requirements",
		},
		{
			name:          "invalid password - fails validation",
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "password123456789", // Explicitly common password to force validation error
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "Password does not meet strength requirements",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt using the encryption key
			encrypted, err := Encrypt(tt.encryptKey, tt.data)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Try to decrypt with the wrong password
			_, err = Decrypt(tt.decryptKey, encrypted)

			// Check if we get the expected error
			if tt.expectError {
				if err == nil {
					t.Error("Decryption should have failed with wrong password")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
			} else if err != nil {
				t.Errorf("Decryption failed unexpectedly: %v", err)
			}
		})
	}
}

func TestDecryptWithCorruptedData(t *testing.T) {
	// First prepare encrypted data for testing
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is a test plaintext for corruption tests."
	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("Failed to create test encrypted data: %v", err)
	}

	tests := []struct {
		name          string
		key           string
		corruptFunc   func(string) string
		expectError   bool
		errorContains string
	}{
		{
			name: "corrupted base64",
			key:  password,
			corruptFunc: func(s string) string {
				return "not-base64-data"
			},
			expectError:   true,
			errorContains: "illegal base64",
		},
		{
			name: "corrupted format",
			key:  password,
			corruptFunc: func(s string) string {
				base64Payload, envelopeMeta, err := parseVisibleCipherEnvelope(s)
				if err != nil {
					return s
				}
				decoded, _ := base64.StdEncoding.DecodeString(base64Payload)
				// Return text too short to break the format
				return encodeCipherForTest(decoded[:20], envelopeMeta)
			},
			expectError:   true,
			errorContains: "invalid ciphertext: too short",
		},
		{
			name: "corrupted hmac",
			key:  password,
			corruptFunc: func(s string) string {
				base64Payload, envelopeMeta, err := parseVisibleCipherEnvelope(s)
				if err != nil {
					return s
				}
				decoded, _ := base64.StdEncoding.DecodeString(base64Payload)
				if len(decoded) > hmacSize {
					// Invert all HMAC bits
					for i := len(decoded) - hmacSize; i < len(decoded); i++ {
						decoded[i] = ^decoded[i] // Invert all bits
					}
				}
				return encodeCipherForTest(decoded, envelopeMeta)
			},
			expectError:   true,
			errorContains: "cipher: message authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corruptedData := tt.corruptFunc(encrypted)
			_, err := Decrypt(tt.key, corruptedData)
			if tt.expectError {
				if err == nil {
					t.Error("Decryption should have failed with corrupted data")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
			} else if err != nil {
				t.Errorf("Decryption failed unexpectedly: %v", err)
			}
		})
	}
}

func TestIndividualAlgorithms(t *testing.T) {
	// This test verifies round-trip encryption/decryption for every supported KDF.
	data := "test data for individual algorithms"
	password := "P@ssw0rd_Str0ng!T3st#2024"

	// Test each algorithm individually
	tests := []struct {
		name      string
		algorithm KeyDerivationAlgorithm
	}{
		{
			name:      "Argon2id",
			algorithm: Argon2idAlgorithm,
		},
		{
			name:      "PBKDF2-SHA256",
			algorithm: PBKDF2SHA256Algorithm,
		},
		{
			name:      "PBKDF2-SHA512",
			algorithm: PBKDF2SHA512Algorithm,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt with specific algorithm
			encrypted, err := Encrypt(password, data, tt.algorithm)
			if err != nil {
				t.Fatalf("Encrypt() with %s error = %v", tt.algorithm, err)
			}

			// Decrypt with same algorithm explicitly
			decrypted, err := Decrypt(password, encrypted)
			if err != nil {
				t.Fatalf("Decrypt() with %s error = %v", tt.algorithm, err)
			}

			// Verify decrypted data matches original
			if decrypted != data {
				t.Errorf("Decrypt() with %s = %v, want %v", tt.algorithm, decrypted, data)
			} else {
				t.Logf("Successfully encrypted and decrypted with %s algorithm", tt.algorithm)
			}
		})
	}
}

func TestDecryptAutoDetectAlgorithm(t *testing.T) {
	password := "P@ssw0rd_Str0ng!T3st#2024"
	data := "algorithm auto-detection payload"

	tests := []struct {
		name      string
		algorithm KeyDerivationAlgorithm
	}{
		{name: "argon2id", algorithm: Argon2idAlgorithm},
		{name: "pbkdf2-sha256", algorithm: PBKDF2SHA256Algorithm},
		{name: "pbkdf2-sha512", algorithm: PBKDF2SHA512Algorithm},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(password, data, tt.algorithm)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			decrypted, err := Decrypt(password, encrypted)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if decrypted != data {
				t.Fatalf("Decrypt() = %q, want %q", decrypted, data)
			}
		})
	}
}

func TestEncryptIncludesMetadataHeader(t *testing.T) {
	password := "P@ssw0rd_Str0ng!T3st#2024"
	data := "metadata header payload"

	encrypted, err := Encrypt(password, data, PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	raw, envelopeMeta := decodeCipherForTest(t, encrypted)
	if envelopeMeta == nil {
		t.Fatal("expected visible envelope metadata, got nil")
	}
	if envelopeMeta.FormatVersion != headerV2Version {
		t.Fatalf("visible metadata format version mismatch: got %d want %d", envelopeMeta.FormatVersion, headerV2Version)
	}
	if envelopeMeta.Algorithm != PBKDF2SHA256Algorithm {
		t.Fatalf("visible metadata algorithm mismatch: got %s want %s", envelopeMeta.Algorithm, PBKDF2SHA256Algorithm)
	}

	if len(raw) < headerV2Length+saltSize+nonceSize+hmacSize {
		t.Fatalf("payload too short for v2 format: %d", len(raw))
	}

	if string(raw[:headerMagicLength]) != headerMagicPrefix {
		t.Fatalf("missing metadata magic prefix, got: %x", raw[:headerMagicLength])
	}

	if raw[headerMagicLength] != byte(headerV2Version) {
		t.Fatalf("unexpected metadata format version: got %d want %d", raw[headerMagicLength], headerV2Version)
	}

	indicatorOffset := headerV2Length - AlgorithmIndicatorLength
	if raw[indicatorOffset] != PBKDF2SHA256Indicator {
		t.Fatalf("unexpected algorithm indicator: got 0x%x want 0x%x", raw[indicatorOffset], PBKDF2SHA256Indicator)
	}
}

func TestExtractMetadata(t *testing.T) {
	password := "P@ssw0rd_Str0ng!T3st#2024"
	data := "metadata extraction payload"

	before := time.Now().UTC().Add(-2 * time.Second)
	encrypted, err := Encrypt(password, data, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	meta, err := ExtractMetadata(encrypted)
	if err != nil {
		t.Fatalf("ExtractMetadata() error = %v", err)
	}

	if meta.FormatVersion != headerV2Version {
		t.Fatalf("metadata format version mismatch: got %d want %d", meta.FormatVersion, headerV2Version)
	}

	if meta.CreatedAt.IsZero() {
		t.Fatal("metadata CreatedAt must be present for v2 ciphertext")
	}

	if meta.CreatedAt.Before(before) || meta.CreatedAt.After(time.Now().UTC().Add(2*time.Second)) {
		t.Fatalf("metadata CreatedAt out of expected range: %v", meta.CreatedAt)
	}
	if meta.Algorithm != Argon2idAlgorithm {
		t.Fatalf("metadata algorithm mismatch: got %s want %s", meta.Algorithm, Argon2idAlgorithm)
	}
}

func TestExtractMetadataLegacyPayload(t *testing.T) {
	password := "P@ssw0rd_Str0ng!T3st#2024"
	data := "legacy metadata payload"

	encrypted, err := Encrypt(password, data, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	raw, _ := decodeCipherForTest(t, encrypted)

	// Convert v2 payload to legacy layout by removing metadata fields before indicator.
	legacyRaw := raw[headerV2Length-AlgorithmIndicatorLength:]
	legacyCiphertext := base64.StdEncoding.EncodeToString(legacyRaw)

	meta, err := ExtractMetadata(legacyCiphertext)
	if err != nil {
		t.Fatalf("ExtractMetadata() error for legacy payload = %v", err)
	}

	if meta.FormatVersion != 1 {
		t.Fatalf("legacy metadata format version mismatch: got %d want 1", meta.FormatVersion)
	}
	if !meta.CreatedAt.IsZero() {
		t.Fatalf("legacy metadata CreatedAt should be zero, got %v", meta.CreatedAt)
	}
	if meta.Algorithm != Argon2idAlgorithm {
		t.Fatalf("legacy metadata algorithm mismatch: got %s want %s", meta.Algorithm, Argon2idAlgorithm)
	}
}

// This test replaces TestEncryptDecryptWithDifferentAlgorithms and TestCompatibilityBetweenAlgorithms
// with a simplified version that focuses only on Argon2id which is working correctly
func TestEncryptDecryptWithArgon2id(t *testing.T) {
	// This test specifically focuses on the Argon2id algorithm which is the primary
	// supported algorithm after our changes to the key derivation and HMAC processes
	data := "test data for argon2id algorithm"
	password := "P@ssw0rd_Str0ng!T3st#2024"
	algorithm := Argon2idAlgorithm

	// Encrypt data with Argon2id
	encrypted, err := Encrypt(password, data, algorithm)
	if err != nil {
		t.Fatalf("Encrypt() with %s error = %v", algorithm, err)
	}

	// Log debugging information
	t.Logf("Using algorithm: %s", algorithm)
	t.Logf("Password length: %d", len(password))
	t.Logf("Encrypted data length: %d", len(encrypted))
	t.Logf("Encrypted first 20 chars: %s", encrypted[:min(20, len(encrypted))])

	// Decrypt the data
	decryptedBuffer, err := Decrypt(password, encrypted)
	if err != nil {
		t.Fatalf("Decrypt() with %s error = %v", algorithm, err)
	}

	// Verify the decrypted data matches the original
	if decryptedBuffer != data {
		t.Errorf("Decrypt() with %s = %v, want %v", algorithm, decryptedBuffer, data)
	} else {
		t.Logf("Successfully encrypted and decrypted with %s algorithm", algorithm)
	}
}

func TestPasswordValidation(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
			errMsg:   "Password does not meet strength requirements",
		},
		{
			name:     "too short password",
			password: "weak",
			wantErr:  true,
			errMsg:   "Password does not meet strength requirements",
		},
		{
			name:     "common password",
			password: "password123456789",
			wantErr:  true,
			errMsg:   "Password does not meet strength requirements",
		},
		{
			name:     "actual strong password",
			password: "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz", // A truly strong password
			wantErr:  false,                            // This should pass all validation checks
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidatePasswordStrength() error = %v, want to contain %v", err, tt.errMsg)
			}
		})
	}
}

func TestBackwardCompatibility(t *testing.T) {
	// In this test we check compatibility with format without algorithm indicator

	// Use the same key and text as in other tests
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is a test plaintext for backward compatibility."

	// 1. Encrypt data using normal Encrypt
	encrypted, err := Encrypt(password, plaintext, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// 2. Verify data can be decrypted normally
	decrypted, err := Decrypt(password, encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected '%s', got '%s'", plaintext, decrypted)
	}

	// 3. Modify encrypted data by removing first 16 bytes (algorithm indicator)
	rawData, _ := decodeCipherForTest(t, encrypted)

	t.Logf("Original encrypted data length: %d bytes", len(rawData))

	// Create old format, excluding algorithm indicator
	legacyData := rawData[AlgorithmIndicatorLength:]
	legacyEncrypted := base64.StdEncoding.EncodeToString(legacyData)

	t.Logf("Legacy format created: %d bytes (original minus %d bytes for algorithm indicator)",
		len(legacyData), AlgorithmIndicatorLength)
	t.Logf("Legacy format base64: %s", legacyEncrypted[:min(50, len(legacyEncrypted))])

	// 4. Should get an error when decrypting legacy format without algorithm indicator
	_, err = Decrypt(password, legacyEncrypted)
	if err == nil {
		t.Error("Expected error when decrypting legacy format, but got none")
	} else {
		t.Logf("Got expected error: %v", err)
	}
}

// TestHMACComputation tests HMAC computation
func TestHMACComputation(t *testing.T) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	data := []byte("test data")

	hmacValue := computeHMAC(key, data, byte('a'))
	if hmacValue == nil {
		t.Fatal("HMAC computation failed")
	}
	if len(hmacValue) != hmacSize {
		t.Errorf("Expected HMAC length %d, got %d", hmacSize, len(hmacValue))
	}
}

// TestHMACFunction tests the consistency of HMAC computation by checking the result is deterministic
func TestHMACFunction(t *testing.T) {
	// This test compares the HMAC computation done by our function with the one from standard library
	// to ensure our secure memory implementation produces the same result as the standard approach

	// Create a fixed test key and data
	key := []byte("fixed-test-key-for-validation")
	data := []byte("fixed-test-data-for-validation")

	// Calculate HMAC using direct HMAC functions (not our wrapper)
	h1 := hmac.New(sha256.New, key)
	h1.Write(data)
	h1.Write([]byte{'a'})
	expected := h1.Sum(nil)

	// Calculate using our function with secure memory
	actual := computeHMAC(key, data, byte('a'))

	// Compare results - they should be identical despite different implementation approaches
	if !bytes.Equal(expected, actual) {
		t.Errorf("HMAC function produces different values than standard library")
		t.Errorf("Expected: %x", expected)
		t.Errorf("Actual: %x", actual)
	} else {
		t.Log("HMAC function matches standard library behavior")
	}
}

func TestKeyDerivation(t *testing.T) {
	password := "P@ssw0rd_Str0ng!T3st#2024"
	salt := []byte("test-salt-for-key-derivation-test")

	// Test Argon2id
	key, err := deriveKey(password, salt, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Argon2id key derivation failed: %v", err)
	}
	if len(key) != Argon2idKeyLen {
		t.Errorf("Expected key length %d, got %d", Argon2idKeyLen, len(key))
	}

	// Test PBKDF2-SHA256
	key, err = deriveKey(password, salt, PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatalf("PBKDF2-SHA256 key derivation failed: %v", err)
	}
	if len(key) != PBKDF2KeyLen {
		t.Errorf("Expected key length %d, got %d", PBKDF2KeyLen, len(key))
	}

	// Test PBKDF2-SHA512
	key, err = deriveKey(password, salt, PBKDF2SHA512Algorithm)
	if err != nil {
		t.Fatalf("PBKDF2-SHA512 key derivation failed: %v", err)
	}
	if len(key) != PBKDF2KeyLen {
		t.Errorf("Expected key length %d, got %d", PBKDF2KeyLen, len(key))
	}
}

// TestDecryptToString tests the DecryptToString function
func TestDecryptToString(t *testing.T) {
	// Setup good data
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is a test plaintext for DecryptToString."

	// Encrypt data for testing
	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("Failed to create test encrypted data: %v", err)
	}

	tests := []struct {
		name          string
		password      string
		encrypted     string
		expectedData  string
		expectError   bool
		errorContains string
	}{
		{
			name:         "valid decryption",
			password:     password,
			encrypted:    encrypted,
			expectedData: plaintext,
		},
		{
			name:          "corrupted data",
			password:      password,
			encrypted:     "not-valid-encrypted-data",
			expectError:   true,
			errorContains: "illegal base64",
		},
		// Test that we handle very short data properly
		{
			name:          "very short data",
			password:      password,
			encrypted:     "short",
			expectError:   true,
			errorContains: "illegal base64",
		},
		// Test with a very short prefix of the actual encrypted data
		{
			name:          "partial encrypted data",
			password:      password,
			encrypted:     encrypted[:10],
			expectError:   true,
			errorContains: "invalid ciphertext envelope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call DecryptToString
			result, err := DecryptToString(tt.encrypted, tt.password)

			// Check error cases
			if tt.expectError {
				if err == nil {
					t.Errorf("DecryptToString() expected error but got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("DecryptToString() error = %v, want to contain %v", err, tt.errorContains)
				}
				return
			}

			// Check success cases
			if err != nil {
				t.Errorf("DecryptToString() unexpected error = %v", err)
				return
			}

			// Verify the result matches the expected data
			if result != tt.expectedData {
				t.Errorf("DecryptToString() = %v, want %v", result, tt.expectedData)
			}
		})
	}
}

// TestGetAvailableKeyDerivationAlgorithms tests the GetAvailableKeyDerivationAlgorithms function
func TestGetAvailableKeyDerivationAlgorithms(t *testing.T) {
	algorithms := GetAvailableKeyDerivationAlgorithms()

	// We should have 3 algorithms
	if len(algorithms) != 3 {
		t.Errorf("GetAvailableKeyDerivationAlgorithms() returned %d algorithms, want 3", len(algorithms))
	}

	// Check that we have the expected algorithms
	expected := map[KeyDerivationAlgorithm]bool{
		Argon2idAlgorithm:     false,
		PBKDF2SHA256Algorithm: false,
		PBKDF2SHA512Algorithm: false,
	}

	for _, alg := range algorithms {
		if _, exists := expected[alg]; !exists {
			t.Errorf("Unexpected algorithm returned: %s", alg)
		} else {
			expected[alg] = true
		}
	}

	// Verify all expected algorithms were found
	for alg, found := range expected {
		if !found {
			t.Errorf("Expected algorithm %s was not returned", alg)
		}
	}
}

// TestSetDefaultAlgorithm tests the SetDefaultAlgorithm function
func TestSetDefaultAlgorithm(t *testing.T) {
	// Save the original default to restore it later
	originalDefault := GetDefaultAlgorithm()
	defer func() {
		SetDefaultAlgorithm(originalDefault)
	}()

	// Set a different algorithm as default
	SetDefaultAlgorithm(PBKDF2SHA256Algorithm)

	// Check that the default was updated
	if GetDefaultAlgorithm() != PBKDF2SHA256Algorithm {
		t.Errorf("Default algorithm not updated, got %s, want %s",
			GetDefaultAlgorithm(), PBKDF2SHA256Algorithm)
	}

	// Set another algorithm
	SetDefaultAlgorithm(PBKDF2SHA512Algorithm)

	// Check that the default was updated again
	if GetDefaultAlgorithm() != PBKDF2SHA512Algorithm {
		t.Errorf("Default algorithm not updated, got %s, want %s",
			GetDefaultAlgorithm(), PBKDF2SHA512Algorithm)
	}

	// Restore the original default which should be Argon2id
	SetDefaultAlgorithm(Argon2idAlgorithm)

	// Check that we're back to the original
	if GetDefaultAlgorithm() != Argon2idAlgorithm {
		t.Errorf("Default algorithm not restored, got %s, want %s",
			GetDefaultAlgorithm(), Argon2idAlgorithm)
	}
}

func TestSetDefaultAlgorithmIgnoresInvalidValue(t *testing.T) {
	originalDefault := GetDefaultAlgorithm()
	defer func() {
		SetDefaultAlgorithm(originalDefault)
	}()

	SetDefaultAlgorithm(Argon2idAlgorithm)
	SetDefaultAlgorithm(KeyDerivationAlgorithm("invalid-algorithm"))

	if got := GetDefaultAlgorithm(); got != Argon2idAlgorithm {
		t.Errorf("Default algorithm changed on invalid input, got %s, want %s", got, Argon2idAlgorithm)
	}
}

func TestSecureLog(t *testing.T) {
	// Enable debug mode temporarily
	origDebug := debugMode
	debugMode = true
	defer func() { debugMode = origDebug }()

	// We just ensure it doesn't panic. Testing output would require capturing stdout.
	secureLog("test %s %d %x", "secret", 123, []byte("secret"))
}

func TestAlgorithmToIndicator(t *testing.T) {
	tests := []struct {
		algo    KeyDerivationAlgorithm
		want    byte
		wantErr bool
	}{
		{Argon2idAlgorithm, Argon2idIndicator, false},
		{PBKDF2SHA256Algorithm, PBKDF2SHA256Indicator, false},
		{PBKDF2SHA512Algorithm, PBKDF2SHA512Indicator, false},
		{"unknown", 0, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			got, err := algorithmToIndicator(tt.algo)
			if (err != nil) != tt.wantErr {
				t.Errorf("algorithmToIndicator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("algorithmToIndicator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecompress_Error(t *testing.T) {
	_, err := decompress([]byte("invalid gzip data"))
	if err == nil {
		t.Error("Expected error from decompress with invalid data")
	}
}

func TestExtractMetadata_Errors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"invalid base64", "v2;ts=123;alg=argon2id;!!!"},
		{"too short", "v2;ts=123;alg=argon2id;" + base64.StdEncoding.EncodeToString([]byte("short"))},
		{"legacy too short", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"unsupported version", "v3;ts=123;alg=argon2id;YWJj"},
		{"missing ts", "v2;invalid=123;alg=argon2id;YWJj"},
		{"missing alg", "v2;ts=123;invalid=argon2id;YWJj"},
		{"malformed ts", "v2;ts=abc;alg=argon2id;YWJj"},
		{"malformed alg", "v2;ts=123;alg=unknown;YWJj"},
		{"empty payload", "v2;ts=123;alg=argon2id;"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractMetadata(tt.data)
			if err == nil {
				t.Errorf("ExtractMetadata() expected error for %s", tt.name)
			}
		})
	}
}

func TestResolveDecryptionAlgorithms(t *testing.T) {
	// Test legacy PBKDF2 logic
	candidates, err := resolveDecryptionAlgorithms(legacyPBKDF2Indicator)
	if err != nil {
		t.Fatalf("resolveDecryptionAlgorithms() error = %v", err)
	}
	if len(candidates) != 2 || candidates[0] != PBKDF2SHA256Algorithm || candidates[1] != PBKDF2SHA512Algorithm {
		t.Errorf("resolveDecryptionAlgorithms(legacyPBKDF2Indicator) = %v", candidates)
	}

	// Test unknown indicator
	_, err = resolveDecryptionAlgorithms(0xFF)
	if err == nil {
		t.Error("resolveDecryptionAlgorithms(0xFF) expected error")
	}

	// Test indicatorToAlgorithm unknown
	_, err = indicatorToAlgorithm(0xFF)
	if err == nil {
		t.Error("indicatorToAlgorithm(0xFF) expected error")
	}

	// Test legacy pbkdf2 indicatorToAlgorithm
	_, err = indicatorToAlgorithm(legacyPBKDF2Indicator)
	if err == nil {
		t.Error("indicatorToAlgorithm(legacyPBKDF2Indicator) expected error")
	}
}

func TestAlgorithmToIndicator_Error(t *testing.T) {
	_, err := algorithmToIndicator("unsupported")
	if err == nil {
		t.Error("algorithmToIndicator() expected error")
	}
}

func TestExtractMetadata_Valid(t *testing.T) {
	// Encrypt some data first to get a valid ciphertext
	key := "HighlySecureAndUniquePass-2024!"
	plaintext := "hello world"
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	meta, err := ExtractMetadata(ciphertext)
	if err != nil {
		t.Fatalf("ExtractMetadata() error = %v", err)
	}

	if meta.Algorithm != Argon2idAlgorithm {
		t.Errorf("ExtractMetadata() algorithm = %v, want %v", meta.Algorithm, Argon2idAlgorithm)
	}
}

func TestPasswordValidation_Coverage(t *testing.T) {
	t.Run("containsCyrillic", func(t *testing.T) {
		if !containsCyrillic("passwordпароль") {
			t.Error("containsCyrillic() should be true for mixed English/Cyrillic")
		}
		if containsCyrillic("password123!") {
			t.Error("containsCyrillic() should be false for English only")
		}
	})
	t.Run("isCommonPassword", func(t *testing.T) {
		if !isCommonPassword("1234567890") {
			t.Error("isCommonPassword() should be true for 1234567890")
		}
		if isCommonPassword("HighlySecureAndUnique-2024!") {
			t.Error("isCommonPassword() should be false for unique password")
		}
	})
}

func TestEncryptStyleSuffix(t *testing.T) {
	key := "HighlySecureAndUniquePass-2024!"
	plaintext := "test data|"
	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if !strings.Contains(encrypted, "v2;") {
		t.Error("Encrypt() should work with style suffix")
	}

	plaintext2 := "test data>"
	_, err = Encrypt(key, plaintext2)
	if err != nil {
		t.Fatalf("Encrypt() with > error = %v", err)
	}
}

func TestDeriveKey_Error(t *testing.T) {
	_, err := deriveKey("pass", nil, "invalid")
	if err == nil {
		t.Error("deriveKey() with invalid algo should return error")
	}
}

func TestIndicatorToAlgorithm_Error(t *testing.T) {
	_, err := indicatorToAlgorithm(0xFF)
	if err == nil {
		t.Error("expected error for invalid indicator")
	}
}

func TestDecryptToString_Error(t *testing.T) {
	_, err := DecryptToString("invalid", "HighlySecureAndUniquePass-2024!")
	if err == nil {
		t.Error("expected error")
	}
}

func TestDeriveKey_Default(t *testing.T) {
	_, err := deriveKey("pass", nil, "unknown")
	if err == nil {
		t.Error("expected error")
	}
}

func TestEncrypt_EmptyAlgoInSlice(t *testing.T) {
	_, err := Encrypt("HighlySecureAndUniquePass-2024!", "data", "")
	if err != nil {
		t.Errorf("Encrypt with empty algo string should use default")
	}
}

func TestMin_Coverage(t *testing.T) {
	if min(1, 2) != 1 {
		t.Error("min(1, 2) != 1")
	}
	if min(2, 1) != 1 {
		t.Error("min(2, 1) != 1")
	}
}

func TestResolveDecryptionAlgorithms_Coverage(t *testing.T) {
	res, err := resolveDecryptionAlgorithms(Argon2idIndicator)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0] != Argon2idAlgorithm {
		t.Errorf("got %v", res)
	}

	_, err = resolveDecryptionAlgorithms(0xFF)
	if err == nil {
		t.Error("expected error for invalid indicator")
	}

	res, err = resolveDecryptionAlgorithms(legacyPBKDF2Indicator)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Errorf("expected 2 algorithms for legacy PBKDF2, got %d", len(res))
	}
}

func TestExtractMetadata_NoEnvelope(t *testing.T) {
	key := "HighlySecureAndUniquePass-2024!"
	encrypted, _ := Encrypt(key, "data")
	parts := strings.Split(encrypted, ";")
	base64Part := parts[len(parts)-1]

	meta, err := ExtractMetadata(base64Part)
	if err != nil {
		t.Errorf("ExtractMetadata failed: %v", err)
	}
	if meta.Algorithm == "" {
		t.Error("expected algorithm to be resolved from payload")
	}
}

func TestEncrypt_InvalidAlgoCoverage(t *testing.T) {
	_, err := Encrypt("HighlySecureAndUniquePass-2024!", "data", "invalid")
	if err == nil {
		t.Error("expected error for invalid algo")
	}
}

func TestExtractMetadata_PayloadTooShortCoverage(t *testing.T) {
	key := "HighlySecureAndUniquePass-2024!"
	encrypted, _ := Encrypt(key, "data")
	parts := strings.Split(encrypted, ";")
	parts[len(parts)-1] = base64.StdEncoding.EncodeToString([]byte("abc"))
	invalidCipher := strings.Join(parts, ";")

	_, err := ExtractMetadata(invalidCipher)
	if err == nil {
		t.Error("expected error for too short payload")
	}
}

func TestParseCipherPayload_WrongMagicCoverage(t *testing.T) {
	payload := []byte("WRONGPAYLOAD")
	_, _, _, _, _, _, _, err := parseCipherPayload(payload)
	if err == nil {
		t.Error("expected error for wrong magic")
	}
}

func TestParseCipherPayload_WrongVersionCoverage(t *testing.T) {
	payload := []byte("YED" + string(byte(0xFF)) + "0000000000" + "a")
	_, _, _, _, _, _, _, err := parseCipherPayload(payload)
	if err == nil {
		t.Error("expected error for wrong version")
	}
}

func TestResolveDecryptionAlgorithms_ExplicitCoverage(t *testing.T) {
	res, err := resolveDecryptionAlgorithms(Argon2idIndicator, PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0] != PBKDF2SHA256Algorithm {
		t.Errorf("got %v", res)
	}
}

func TestIndicatorToAlgorithm_AllCoverage(t *testing.T) {
	indicators := []byte{Argon2idIndicator, legacyArgon2Indicator, PBKDF2SHA256Indicator, PBKDF2SHA512Indicator}
	for _, ind := range indicators {
		_, err := indicatorToAlgorithm(ind)
		if err != nil {
			t.Errorf("failed for %x", ind)
		}
	}

	_, err := indicatorToAlgorithm(legacyPBKDF2Indicator)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("expected ambiguous error for legacy PBKDF2, got %v", err)
	}
}

func TestMin_EqualCoverage(t *testing.T) {
	if min(1, 1) != 1 {
		t.Error("min(1, 1) != 1")
	}
}

func TestAlgorithmToIndicator_DefaultCoverage(t *testing.T) {
	_, err := algorithmToIndicator("unknown")
	if err == nil {
		t.Error("expected error")
	}
}

func TestParseCipherPayload_TooShortCoverage(t *testing.T) {
	payload := make([]byte, 57)
	copy(payload, "YED")
	payload[3] = byte(headerV2Version)
	_, _, _, _, _, _, _, err := parseCipherPayload(payload)
	if err == nil {
		t.Error("expected error for too short payload")
	}
}

func TestParseCipherPayload_InvalidTimestampCoverage(t *testing.T) {
	payload := make([]byte, 91)
	copy(payload, "YED")
	payload[3] = byte(headerV2Version)
	copy(payload[4:], "XXXXXXXXXX")
	_, _, _, _, _, _, _, err := parseCipherPayload(payload)
	if err == nil {
		t.Error("expected error for invalid timestamp")
	}
}

func TestDecrypt_EnvelopeErrorCoverage(t *testing.T) {
	_, err := Decrypt("HighlySecureAndUniquePass-2024!", "v2;too;short")
	if err == nil {
		t.Error("expected error")
	}
}

func TestParseVisibleCipherEnvelope_InvalidTimestampCoverage(t *testing.T) {
	_, _, err := parseVisibleCipherEnvelope("v2;ts=XXX;alg=a;base64")
	if err == nil {
		t.Error("expected error")
	}
}

func TestParseVisibleCipherEnvelope_ErrorsCoverage(t *testing.T) {
	_, _, err := parseVisibleCipherEnvelope("v2;ts=123;alg=argon2id") // missing payload
	if err == nil {
		t.Error("expected malformed structure error")
	}

	_, _, err = parseVisibleCipherEnvelope("v2;xs=123;alg=argon2id;base64") // missing ts

	if err == nil {
		t.Error("expected missing ts field error")
	}

	_, _, err = parseVisibleCipherEnvelope("v2;ts=123;xlg=argon2id;base64") // missing alg
	if err == nil {
		t.Error("expected missing alg field error")
	}

	_, _, err = parseVisibleCipherEnvelope("v2;ts=123;alg=argon2id;") // empty payload
	if err == nil {
		t.Error("expected empty payload error")
	}
}

func TestExtractMetadata_EmptyAndInvalidBase64(t *testing.T) {
	_, err := ExtractMetadata("")
	if err == nil {
		t.Error("expected error for empty ciphertext")
	}

	_, err = ExtractMetadata("v2;ts=1714580000;alg=argon2id;invalid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestExtractMetadata_EnvelopeMetaMerge(t *testing.T) {
	// Create a valid encrypted string
	key := "HighlySecureAndUniquePass-2024!"
	encrypted, _ := Encrypt(key, "data")

	// We can't easily change meta.FormatVersion because it's inside the encrypted payload.
	// But we can test if meta.CreatedAt is merged when it's zero in the payload (unlikely)
	// or just hit the lines.
	meta, err := ExtractMetadata(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if meta.FormatVersion != 2 {
		t.Errorf("expected format version 2, got %d", meta.FormatVersion)
	}
}

func TestSecureLog_Coverage(t *testing.T) {
	orig := debugMode
	debugMode = true
	defer func() { debugMode = orig }()
	secureLog("test %s", "arg")
}

func TestExtractMetadata_MalformedPayloadCoverage(t *testing.T) {
	// Valid magic but wrong version
	payload := []byte("YED" + string(byte(0xFF)) + strings.Repeat("0", 54))
	b64 := base64.StdEncoding.EncodeToString(payload)
	_, err := ExtractMetadata(b64)
	if err == nil {
		t.Error("expected error for wrong version")
	}
}

func TestExtractMetadata_MergeCoverage(t *testing.T) {
	// Binary payload with version 1 (no YED prefix, treated as legacy)
	binary := make([]byte, 77)
	binary[0] = Argon2idIndicator
	b64 := base64.StdEncoding.EncodeToString(binary)
	// Envelope with version 2
	env := "v2;ts=1714580000;alg=argon2id;" + b64
	meta, err := ExtractMetadata(env)
	if err != nil {
		t.Fatal(err)
	}
	if meta.FormatVersion != 2 {
		t.Errorf("expected version 2 from envelope, got %d", meta.FormatVersion)
	}
	if meta.Algorithm != Argon2idAlgorithm {
		t.Errorf("expected algo argon2id from envelope, got %s", meta.Algorithm)
	}
}

func TestParseCipherPayload_WrongVersionLongCoverage(t *testing.T) {
	payload := make([]byte, 91)
	copy(payload, "YED")
	payload[3] = byte(0xFF)
	_, _, _, _, _, _, _, err := parseCipherPayload(payload)
	if err == nil {
		t.Error("expected error for wrong version")
	}
}
