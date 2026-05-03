package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
)

var (
	// Named logger for benchmark component
	benchmarkLogger = logger.Named("benchmark")
)

const (
	// TestPassword is a strong password used for benchmark testing only
	TestPassword = "P@ssw0rd_Str0ng!T3st#2024"

	// NanosecondsPerSecond is the number of nanoseconds in one second
	NanosecondsPerSecond = 1000000000

	// BenchmarkFilePermissions defines secure file permissions for benchmark results
	BenchmarkFilePermissions = 0600
)

// benchmarkResult represents a single benchmark result
type benchmarkResult struct {
	Category    string
	Name        string
	Operations  int
	NsPerOp     float64
	BytesPerOp  int
	AllocsPerOp int
}

// runBenchmarks executes all benchmarks and outputs results
func runBenchmarks(outputFile string) int {
	fmt.Println("Running benchmarks...")

	results := []benchmarkResult{}

	// Run key derivation algorithm benchmarks
	keyDerivationResults := runKeyDerivationBenchmarks()
	results = append(results, keyDerivationResults...)

	// Run encryption benchmarks
	encryptionResults := runEncryptionBenchmarks()
	results = append(results, encryptionResults...)

	// Run decryption benchmarks
	decryptionResults := runDecryptionBenchmarks()
	results = append(results, decryptionResults...)

	// Output results
	if err := outputBenchmarkResults(results, outputFile); err != nil {
		benchmarkLogger.Error("Failed to output benchmark results", zap.Error(err))
		return 1
	}

	return 0
}

// runKeyDerivationBenchmarks runs benchmarks for key derivation algorithms
func runKeyDerivationBenchmarks() []benchmarkResult {
	fmt.Println("Running key derivation algorithm benchmarks...")

	results := []benchmarkResult{}

	// Benchmark Argon2id
	argon2Result := runSingleBenchmark("Key Derivation", "Argon2id", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := encryption.Encrypt(TestPassword, "test", encryption.Argon2idAlgorithm)
			if err != nil {
				b.Fatalf("Key derivation failed: %v", err)
			}
		}
	})
	results = append(results, argon2Result)

	// Benchmark PBKDF2-SHA256
	pbkdf2Sha256Result := runSingleBenchmark("Key Derivation", "PBKDF2-SHA256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := encryption.Encrypt(TestPassword, "test", encryption.PBKDF2SHA256Algorithm)
			if err != nil {
				b.Fatalf("Key derivation failed: %v", err)
			}
		}
	})
	results = append(results, pbkdf2Sha256Result)

	// Benchmark PBKDF2-SHA512
	pbkdf2Sha512Result := runSingleBenchmark("Key Derivation", "PBKDF2-SHA512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := encryption.Encrypt(TestPassword, "test", encryption.PBKDF2SHA512Algorithm)
			if err != nil {
				b.Fatalf("Key derivation failed: %v", err)
			}
		}
	})
	results = append(results, pbkdf2Sha512Result)

	return results
}

// runEncryptionBenchmarks runs benchmarks for encryption
func runEncryptionBenchmarks() []benchmarkResult {
	fmt.Println("Running encryption benchmarks...")
	plaintext := "This is sensitive data that needs to be encrypted"

	results := []benchmarkResult{}

	// Basic encryption
	encryptResult := runSingleBenchmark("Encryption", "Standard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := encryption.Encrypt(TestPassword, plaintext)
			if err != nil {
				b.Fatalf("Encryption failed: %v", err)
			}
		}
	})
	results = append(results, encryptResult)

	// Encryption with different algorithms
	algorithms := []encryption.KeyDerivationAlgorithm{
		encryption.Argon2idAlgorithm,
		encryption.PBKDF2SHA256Algorithm,
		encryption.PBKDF2SHA512Algorithm,
	}

	for _, algo := range algorithms {
		algoName := string(algo)
		// Make algorithm names more readable
		switch algo {
		case encryption.PBKDF2SHA256Algorithm:
			algoName = "PBKDF2-SHA256"
		case encryption.PBKDF2SHA512Algorithm:
			algoName = "PBKDF2-SHA512"
		}

		result := runSingleBenchmark("Encryption", algoName, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := encryption.Encrypt(TestPassword, plaintext, algo)
				if err != nil {
					b.Fatalf("Encryption with %s failed: %v", algo, err)
				}
			}
		})
		results = append(results, result)
	}

	return results
}

// runDecryptionBenchmarks runs benchmarks for decryption
func runDecryptionBenchmarks() []benchmarkResult {
	fmt.Println("Running decryption benchmarks...")
	plaintext := "This is sensitive data that needs to be encrypted"

	results := []benchmarkResult{}

	// Prepare standard encrypted data
	encrypted, err := encryption.Encrypt(TestPassword, plaintext)
	if err != nil {
		benchmarkLogger.Error("Failed to prepare encrypted data for benchmark")
		return results
	}

	// Basic decryption
	decryptResult := runSingleBenchmark("Decryption", "Standard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := encryption.DecryptToString(encrypted, TestPassword)
			if err != nil {
				b.Fatalf("Decryption failed: %v", err)
			}
		}
	})
	results = append(results, decryptResult)

	// Decryption with different algorithms
	algorithms := []encryption.KeyDerivationAlgorithm{
		encryption.Argon2idAlgorithm,
		encryption.PBKDF2SHA256Algorithm,
		encryption.PBKDF2SHA512Algorithm,
	}

	// Prepare encrypted data for each algorithm
	encryptedData := make(map[encryption.KeyDerivationAlgorithm]string)
	for _, algo := range algorithms {
		encrypted, err := encryption.Encrypt(TestPassword, plaintext, algo)
		if err != nil {
			benchmarkLogger.Error("Failed to prepare encrypted data for algorithm",
				zap.String("algorithm", string(algo)),
				zap.Error(err))
			continue
		}
		encryptedData[algo] = encrypted
	}

	for _, algo := range algorithms {
		encrypted, ok := encryptedData[algo]
		if !ok {
			continue
		}

		algoName := string(algo)
		// Make algorithm names more readable
		switch algo {
		case encryption.PBKDF2SHA256Algorithm:
			algoName = "PBKDF2-SHA256"
		case encryption.PBKDF2SHA512Algorithm:
			algoName = "PBKDF2-SHA512"
		}

		result := runSingleBenchmark("Decryption", algoName, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := encryption.DecryptToString(encrypted, TestPassword)
				if err != nil {
					b.Fatalf("Decryption with %s failed. Please check the error logs for details.", algo)
				}
			}
		})
		results = append(results, result)
	}

	return results
}

// runSingleBenchmark runs a single benchmark and returns its result
func runSingleBenchmark(category, name string, fn func(b *testing.B)) benchmarkResult {
	result := testing.Benchmark(fn)
	return benchmarkResult{
		Category:    category,
		Name:        name,
		Operations:  result.N,
		NsPerOp:     float64(result.T.Nanoseconds()) / float64(result.N),
		BytesPerOp:  int(result.AllocedBytesPerOp()),
		AllocsPerOp: int(result.AllocsPerOp()),
	}
}

// outputBenchmarkResults outputs benchmark results to a file or stdout
func outputBenchmarkResults(results []benchmarkResult, outputFile string) error {
	// Format as Markdown table
	var output strings.Builder

	// Add header
	output.WriteString("# Benchmark Results\n\n")
	fmt.Fprintf(&output, "Generated on `%s`\n\n", time.Now().Format(time.RFC1123))

	// Group results by category
	categories := make(map[string][]benchmarkResult)
	for _, r := range results {
		categories[r.Category] = append(categories[r.Category], r)
	}

	// Sort category keys for deterministic output
	categoryKeys := make([]string, 0, len(categories))
	for category := range categories {
		categoryKeys = append(categoryKeys, category)
	}
	sort.Strings(categoryKeys)

	// Output each category
	for _, category := range categoryKeys {
		categoryResults := categories[category]
		fmt.Fprintf(&output, "## %s\n\n", category)
		output.WriteString("| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |\n")
		output.WriteString("|-----------|----------------|--------------|---------------|----------|\n")

		for _, r := range categoryResults {
			opsPerSec := float64(NanosecondsPerSecond) / r.NsPerOp
			fmt.Fprintf(&output, "| %s | %.2f | %.2f | %d | %d |\n",
				r.Name, opsPerSec, r.NsPerOp, r.BytesPerOp, r.AllocsPerOp)
		}

		output.WriteString("\n")
	}

	// Output to file or stdout
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(output.String()), BenchmarkFilePermissions); err != nil {
			return fmt.Errorf("failed to write benchmark results to file: %v", err)
		}
		fmt.Printf("Benchmark results written to %s\n", outputFile)
	} else {
		fmt.Println(output.String())
	}

	return nil
}

// runEncryptionBenchmarkWithParams runs encryption benchmark with specific parameters
func runEncryptionBenchmarkWithParams(b *testing.B, password string, plaintext string) {
	b.Run("Encryption", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := encryption.Encrypt(password, plaintext)
			if err != nil {
				b.Fatalf("Encryption failed: %v", err)
			}
		}
	})
}

// runDecryptionBenchmarkWithParams runs decryption benchmark with specific parameters
func runDecryptionBenchmarkWithParams(b *testing.B, password string, encrypted string) {
	b.Run("Decryption", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := encryption.DecryptToString(encrypted, password)
			if err != nil {
				b.Fatalf("Decryption failed: %v", err)
			}
		}
	})
}

// BenchmarkEncryptionDecryption runs benchmarks for encryption and decryption
func BenchmarkEncryptionDecryption(b *testing.B) {
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is a test string for benchmarking."

	// First encrypt the data
	encrypted, err := encryption.Encrypt(password, plaintext)
	if err != nil {
		b.Fatalf("Failed to encrypt data for benchmark: %v", err)
	}

	// Run encryption benchmark
	runEncryptionBenchmarkWithParams(b, password, plaintext)

	// Run decryption benchmark
	runDecryptionBenchmarkWithParams(b, password, encrypted)
}
