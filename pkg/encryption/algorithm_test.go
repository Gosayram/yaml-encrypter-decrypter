package encryption

import (
	"strings"
	"testing"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
)

func TestValidateAlgorithm(t *testing.T) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting TestValidateAlgorithm")

	tests := []struct {
		name          string
		algorithm     string
		expected      KeyDerivationAlgorithm
		expectError   bool
		errorContains string
	}{
		{
			name:      "empty algorithm string returns default",
			algorithm: "",
			expected:  GetDefaultAlgorithm(),
		},
		{
			name:      "argon2id lowercase",
			algorithm: "argon2id",
			expected:  Argon2idAlgorithm,
		},
		{
			name:      "argon2id mixed case",
			algorithm: "ArGon2Id",
			expected:  Argon2idAlgorithm,
		},
		{
			name:      "pbkdf2-sha256 lowercase",
			algorithm: "pbkdf2-sha256",
			expected:  PBKDF2SHA256Algorithm,
		},
		{
			name:      "pbkdf2-sha512 lowercase",
			algorithm: "pbkdf2-sha512",
			expected:  PBKDF2SHA512Algorithm,
		},
		{
			name:      "algorithm with surrounding spaces",
			algorithm: "  pbkdf2-sha256  ",
			expected:  PBKDF2SHA256Algorithm,
		},
		{
			name:          "invalid algorithm",
			algorithm:     "invalid-algorithm",
			expectError:   true,
			errorContains: "invalid algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateAlgorithm(tt.algorithm)

			// Check error cases
			if tt.expectError {
				if err == nil {
					t.Errorf("ValidateAlgorithm() expected error but got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("ValidateAlgorithm() error = %v, want to contain %v", err, tt.errorContains)
				}
				return
			}

			// Check success cases
			if err != nil {
				t.Errorf("ValidateAlgorithm() unexpected error = %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("ValidateAlgorithm() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetAvailableAlgorithms(t *testing.T) {
	algorithms := GetAvailableAlgorithms()

	// Check that we got the expected number of algorithms
	if len(algorithms) != 3 {
		t.Errorf("GetAvailableAlgorithms() returned %d algorithms, want 3", len(algorithms))
	}

	// Check that all expected algorithms are present
	expectedAlgorithms := map[string]bool{
		"argon2id":      false,
		"pbkdf2-sha256": false,
		"pbkdf2-sha512": false,
	}

	for _, algo := range algorithms {
		if _, exists := expectedAlgorithms[algo]; !exists {
			t.Errorf("GetAvailableAlgorithms() returned unexpected algorithm: %s", algo)
		} else {
			expectedAlgorithms[algo] = true
		}
	}

	// Check that all expected algorithms were found
	for algo, found := range expectedAlgorithms {
		if !found {
			t.Errorf("GetAvailableAlgorithms() did not return expected algorithm: %s", algo)
		}
	}
}
