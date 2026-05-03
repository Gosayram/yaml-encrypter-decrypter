package main

import (
	"os"
	"strings"
	"testing"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
)

func TestOutputBenchmarkResults(t *testing.T) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting TestOutputBenchmarkResults")

	// Create test data
	results := []benchmarkResult{
		{
			Category:    "Key Derivation",
			Name:        "Argon2id",
			Operations:  1000,
			NsPerOp:     500000.0,
			BytesPerOp:  1024,
			AllocsPerOp: 10,
		},
		{
			Category:    "Key Derivation",
			Name:        "PBKDF2",
			Operations:  2000,
			NsPerOp:     250000.0,
			BytesPerOp:  512,
			AllocsPerOp: 5,
		},
		{
			Category:    "Encryption",
			Name:        "AES-256-GCM",
			Operations:  5000,
			NsPerOp:     40000.0,
			BytesPerOp:  256,
			AllocsPerOp: 3,
		},
	}

	// Create temporary file for output
	tempFile := "test_benchmark_results.md"
	defer func() { _ = os.Remove(tempFile) }() // Delete file after test completes

	// Call the function under test
	err := outputBenchmarkResults(results, tempFile)
	if err != nil {
		t.Fatalf("outputBenchmarkResults returned error: %v", err)
	}

	// Check that the file was created
	_, err = os.Stat(tempFile)
	if os.IsNotExist(err) {
		t.Fatalf("Expected benchmark results file was not created")
	}

	// Read file contents
	content, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatalf("Failed to read benchmark results file: %v", err)
	}

	// Check that content is not empty
	if len(content) == 0 {
		t.Errorf("Benchmark results file is empty")
	}

	// Check that file contains expected table headers
	expectedHeaders := []string{
		"# Benchmark Results",
		"Generated on",
		"## Key Derivation",
		"| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |",
		"| Argon2id |",
		"| PBKDF2 |",
		"## Encryption",
		"| AES-256-GCM |",
	}

	contentStr := string(content)
	for _, header := range expectedHeaders {
		if !contains(contentStr, header) {
			t.Errorf("Expected content to contain '%s', but it doesn't", header)
		}
	}

	// Check output without file (to stdout)
	err = outputBenchmarkResults(results[:1], "")
	if err != nil {
		t.Fatalf("outputBenchmarkResults to stdout returned error: %v", err)
	}
}

// Helper function to check string content
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
