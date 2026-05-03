package encryption

import (
	"strings"
	"testing"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
)

func TestValidatePasswordStrength(t *testing.T) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting TestValidatePasswordStrength")

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "P@ssw0rd_Str0ng!T3st#2024",
			wantErr:  false,
		},
		{
			name:     "too short password",
			password: "short",
			wantErr:  true,
		},
		{
			name:     "too long password",
			password: strings.Repeat("a", 65),
			wantErr:  true,
		},
		{
			name:     "common password",
			password: "password123456789",
			wantErr:  true,
		},
		{
			name:     "exact 15-char lowercase allowed",
			password: strings.Repeat("a", 15),
			wantErr:  false,
		},
		{
			name:     "long passphrase without character diversity still allowed",
			password: "correcthorsebatterystaple",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePasswordStrength_NoCharacterClassRequirement(t *testing.T) {
	password := "correcthorsebatterystaple"
	if err := ValidatePasswordStrength(password); err != nil {
		t.Fatalf("expected long passphrase without forced char classes to be valid, got error: %v", err)
	}
}

func TestCalculatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     string
	}{
		{
			name:     "low strength password",
			password: "password123456789",
			want:     PasswordMediumStrength,
		},
		{
			name:     "medium strength password",
			password: "P@ssw0rd12345678",
			want:     PasswordHighStrength,
		},
		{
			name:     "high strength password",
			password: "P@ssw0rd_Str0ng!T3st#2024",
			want:     PasswordHighStrength,
		},
		{
			name:     "short password",
			password: "P@ss1",
			want:     PasswordLowStrength,
		},
		{
			name:     "long password with two types",
			password: "PasswordPasswordPassword",
			want:     PasswordMediumStrength,
		},
		{
			name:     "password with three types",
			password: "P@ssw0rd12345678",
			want:     PasswordHighStrength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculatePasswordStrength(tt.password); got != tt.want {
				t.Errorf("calculatePasswordStrength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSuggestPasswordImprovement(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantAny  []string
	}{
		{
			name:     "missing uppercase",
			password: "password123456789!",
			wantAny:  []string{"Add uppercase letters"},
		},
		{
			name:     "missing lowercase",
			password: "PASSWORD123456789!",
			wantAny:  []string{"Add lowercase letters"},
		},
		{
			name:     "missing digits",
			password: "Password!Password!",
			wantAny:  []string{"Add numbers"},
		},
		{
			name:     "missing special chars",
			password: "Password123456789",
			wantAny:  []string{"Add special characters"},
		},
		{
			name:     "short but complex",
			password: "P@ss1",
			wantAny:  []string{"Increase password length"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SuggestPasswordImprovement(tt.password)

			for _, wantSuggestion := range tt.wantAny {
				found := false
				for _, suggestion := range got {
					if suggestion != "" && willFind(suggestion, wantSuggestion) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("SuggestPasswordImprovement() should contain '%s', got %v", wantSuggestion, got)
				}
			}
		})
	}
}

// willFind checks if a string contains another string
func willFind(s, substr string) bool {
	return s == substr || contains(s, substr)
}

// contains checks if a string contains another string
func contains(s, substr string) bool {
	for i := 0; i < len(s); i++ {
		if i+len(substr) <= len(s) && s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestPasswordStrengthErrorError tests the Error method of PasswordStrengthError
func TestPasswordStrengthErrorError(t *testing.T) {
	tests := []struct {
		name          string
		err           *PasswordStrengthError
		expectedError string
	}{
		{
			name: "basic error message",
			err: &PasswordStrengthError{
				Message:   "Test error message",
				Problems:  []string{"Problem 1", "Problem 2"},
				Strength:  "Low",
				IsCommon:  false,
				MinLength: 15,
				MaxLength: 64,
			},
			expectedError: "Test error message",
		},
		{
			name: "error with empty message",
			err: &PasswordStrengthError{
				Message:   "",
				Problems:  []string{"Problem 1", "Problem 2"},
				Strength:  "Low",
				IsCommon:  false,
				MinLength: 15,
				MaxLength: 64,
			},
			expectedError: "",
		},
		{
			name: "error with no problems",
			err: &PasswordStrengthError{
				Message:   "Test error message",
				Problems:  []string{},
				Strength:  "Low",
				IsCommon:  false,
				MinLength: 15,
				MaxLength: 64,
			},
			expectedError: "Test error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorMessage := tt.err.Error()

			if errorMessage != tt.expectedError {
				t.Errorf("Error() = %v, want %v", errorMessage, tt.expectedError)
			}
		})
	}
}

// TestIsPasswordBreached tests the IsPasswordBreached function
func TestIsPasswordBreached(t *testing.T) {
	tests := []struct {
		name             string
		password         string
		expectedBreached bool
		expectError      bool
	}{
		{
			name:             "common password",
			password:         "password123",
			expectedBreached: true,
		},
		{
			name:             "secure password",
			password:         "P@ssw0rd_Str0ng!T3st#2024",
			expectedBreached: false,
		},
		{
			name:             "empty password",
			password:         "",
			expectedBreached: false, // Current implementation just checks common passwords
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isBreached, err := IsPasswordBreached(tt.password)

			// Check error cases
			if tt.expectError {
				if err == nil {
					t.Errorf("IsPasswordBreached() expected error but got nil")
				}
				return
			}

			// No errors expected in the current implementation
			if err != nil {
				t.Errorf("IsPasswordBreached() unexpected error = %v", err)
				return
			}

			// Check the breach status
			if isBreached != tt.expectedBreached {
				t.Errorf("IsPasswordBreached() = %v, want %v", isBreached, tt.expectedBreached)
			}
		})
	}
}
