package encryption

import (
	"strings"
	"testing"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
)

func BenchmarkEncrypt(b *testing.B) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting BenchmarkEncrypt")

	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := strings.Repeat("This is a test. ", 100)

	for i := 0; i < b.N; i++ {
		_, err := Encrypt(password, plaintext)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting BenchmarkDecrypt")

	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := strings.Repeat("This is a test. ", 100)

	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(password, encrypted)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkEncryptionWithAlgorithms compares the performance of encryption with different algorithms
func BenchmarkEncryptionWithAlgorithms(b *testing.B) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting BenchmarkEncryptionWithAlgorithms")

	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is sensitive data that needs to be encrypted"

	algorithms := []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}

	for _, algo := range algorithms {
		b.Run(string(algo), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := Encrypt(password, plaintext, algo)
				if err != nil {
					b.Fatalf("Encryption with %s failed: %v", algo, err)
				}
			}
		})
	}
}

// BenchmarkDecryptionWithAlgorithms compares the performance of decryption with different algorithms
func BenchmarkDecryptionWithAlgorithms(b *testing.B) {
	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is sensitive data that needs to be encrypted"

	algorithms := []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}

	// Prepare encrypted data in advance
	encryptedData := make(map[KeyDerivationAlgorithm]string)

	for _, algo := range algorithms {
		encrypted, err := Encrypt(password, plaintext, algo)
		if err != nil {
			b.Fatalf("Pre-encryption with %s failed: %v", algo, err)
		}
		encryptedData[algo] = encrypted
	}

	b.ResetTimer()

	for _, algo := range algorithms {
		b.Run(string(algo), func(b *testing.B) {
			encrypted := encryptedData[algo]
			for i := 0; i < b.N; i++ {
				// Explicitly specify the algorithm for decryption to avoid authentication errors
				_, err := Decrypt(password, encrypted, algo)
				if err != nil {
					b.Fatalf("Decryption with %s failed: %v", algo, err)
				}
			}
		})
	}
}

// BenchmarkKeyDerivationAlgorithms compares the performance of different key derivation algorithms
func BenchmarkKeyDerivationAlgorithms(b *testing.B) {
	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	salt := []byte("Random_Salt_For_Testing_Benchmarks")

	// Test each key derivation algorithm
	algorithms := []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}

	for _, algo := range algorithms {
		b.Run(string(algo), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key, err := deriveKey(password, salt, algo)
				if err != nil {
					b.Fatalf("Key derivation with %s failed: %v", algo, err)
				}
				// Ensure key is used to prevent compiler optimizations
				if len(key) == 0 {
					b.Fatalf("Key derivation produced empty key")
				}
			}
		})
	}
}

// BenchmarkArgon2Configs compares the performance of different Argon2 configurations
func BenchmarkArgon2Configs(b *testing.B) {
	// Define a set of Argon2 configurations to test
	configs := []struct {
		name       string
		iterations uint32
		memory     uint32
		threads    uint8
		keyLength  int
	}{
		{"OWASP-1-current", 1, 64 * 1024, 4, 32},         // Current settings
		{"OWASP-2-more-iterations", 2, 64 * 1024, 4, 32}, // Increased time cost
		{"OWASP-3-max-iterations", 3, 64 * 1024, 4, 32},  // Further increased time cost
		{"Previous-Config", 1, 32 * 1024, 2, 32},         // Previous/older configuration
	}

	password := "P@ssw0rd_Str0ng!T3st#2024"
	salt := []byte("Random_Salt_For_Testing_Benchmarks")

	// Save the original values
	originalIterations := argon2Iterations
	originalMem := argon2Memory
	originalThreads := argon2Threads

	// Restore original values after the benchmark
	defer func() {
		argon2Iterations = originalIterations
		argon2Memory = originalMem
		argon2Threads = originalThreads
	}()

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			// Set the Argon2 parameters for this benchmark
			argon2Iterations = cfg.iterations
			argon2Memory = cfg.memory
			argon2Threads = cfg.threads

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key, err := deriveKey(password, salt, Argon2idAlgorithm)
				if err != nil {
					b.Fatalf("Key derivation failed: %v", err)
				}
				// Ensure key is used to prevent compiler optimizations
				if len(key) == 0 {
					b.Fatalf("Key derivation produced empty key")
				}
			}
		})
	}
}

func TestPBKDF2SHA256Iterations(t *testing.T) {
	// Save the original value
	originalIterations := pbkdf2SHA256Iterations
	defer func() { pbkdf2SHA256Iterations = originalIterations }()

	// Set the test value
	pbkdf2SHA256Iterations = 1000

	// Test key derivation
	key, err := deriveKey("test-password", []byte("test-salt"), PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	if len(key) != PBKDF2KeyLen {
		t.Errorf("Expected key length %d, got %d", PBKDF2KeyLen, len(key))
	}
}

func TestPBKDF2SHA512Iterations(t *testing.T) {
	// Save the original value
	originalIterations := pbkdf2SHA512Iterations
	defer func() { pbkdf2SHA512Iterations = originalIterations }()

	// Set the test value
	pbkdf2SHA512Iterations = 1000

	// Test key derivation
	key, err := deriveKey("test-password", []byte("test-salt"), PBKDF2SHA512Algorithm)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	if len(key) != PBKDF2KeyLen {
		t.Errorf("Expected key length %d, got %d", PBKDF2KeyLen, len(key))
	}
}
