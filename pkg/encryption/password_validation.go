package encryption

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// PasswordMinLength is the minimum recommended password length (NIST SP800-63B)
	PasswordMinLength = 15

	// PasswordMaxLength is the maximum supported password length (NIST SP800-63B)
	// Allowing long passwords for passphrases while preventing DoS attacks
	PasswordMaxLength = 64

	// PasswordRecommendedLength is the recommended minimum password length for enhanced security
	PasswordRecommendedLength = 15

	// PasswordLowStrength represents a password with only one character type
	PasswordLowStrength = "Low"

	// PasswordMediumStrength represents a password with two or three character types
	PasswordMediumStrength = "Medium"

	// PasswordHighStrength represents a password with all character types
	PasswordHighStrength = "High"

	// AllowedSpecialChars contains the set of allowed special characters according to OWASP
	AllowedSpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// OneCharType is the count for one character type in password
	OneCharType = 1
	// TwoCharTypes is the count for two character types in password
	TwoCharTypes = 2
	// ThreeCharTypes is the count for three character types in password
	ThreeCharTypes = 3
	// FourCharTypes is the count for four character types in password
	FourCharTypes = 4
)

var (
	// Common breached passwords to block (this should be expanded or use an API like Pwned Passwords)
	commonPasswords = map[string]bool{
		"password":          true,
		"123456":            true,
		"qwerty":            true,
		"admin":             true,
		"welcome":           true,
		"123456789":         true,
		"12345678":          true,
		"abc123":            true,
		"password1":         true,
		"password123":       true,
		"iloveyou":          true,
		"1234567":           true,
		"12345":             true,
		"monkey":            true,
		"letmein":           true,
		"dragon":            true,
		"baseball":          true,
		"sunshine":          true,
		"princess":          true,
		"superman":          true,
		"trustno1":          true,
		"1234":              true,
		"password123456789": true,
	}
)

// PasswordStrengthError represents errors related to password strength
type PasswordStrengthError struct {
	Message   string   `json:"message"`
	Problems  []string `json:"problems"`
	Strength  string   `json:"strength"`
	IsCommon  bool     `json:"is_common"`
	MinLength int      `json:"min_length"`
	MaxLength int      `json:"max_length"`
}

// Error returns the error message
func (e *PasswordStrengthError) Error() string {
	return e.Message
}

// ValidatePasswordStrength checks if a password meets strength requirements
func ValidatePasswordStrength(password string) error {
	var problems []string

	// Check for Cyrillic characters
	if containsCyrillic(password) {
		problems = append(problems, "Password must not contain Cyrillic characters")
	}

	// Check password length
	if len(password) < PasswordMinLength {
		problems = append(problems, fmt.Sprintf("Password must be at least %d characters long", PasswordMinLength))
	}

	if len(password) > PasswordMaxLength {
		problems = append(problems, fmt.Sprintf("Password must not exceed %d characters", PasswordMaxLength))
	}

	// Check if it's a common password
	if isCommonPassword(password) {
		problems = append(problems, "Password is too common and easily guessable")
	}

	strength := calculatePasswordStrength(password)

	// If we found problems, return them
	if len(problems) > 0 {
		return &PasswordStrengthError{
			Message:   "Password does not meet strength requirements",
			Problems:  problems,
			Strength:  strength,
			IsCommon:  isCommonPassword(password),
			MinLength: PasswordMinLength,
			MaxLength: PasswordMaxLength,
		}
	}
	return nil
}

// containsCyrillic checks if the string contains any Cyrillic characters
func containsCyrillic(s string) bool {
	for _, r := range s {
		if (r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё' {
			return true
		}
	}
	return false
}

// calculatePasswordStrength rates the password strength
func calculatePasswordStrength(password string) string {
	if len(password) < PasswordMinLength {
		return PasswordLowStrength
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case strings.ContainsRune(AllowedSpecialChars, char):
			hasSpecial = true
		}
	}

	// Count character types
	charTypes := 0
	if hasUpper {
		charTypes++
	}
	if hasLower {
		charTypes++
	}
	if hasDigit {
		charTypes++
	}
	if hasSpecial {
		charTypes++
	}

	// Rate the password based on number of character types
	switch charTypes {
	case OneCharType:
		return PasswordLowStrength
	case TwoCharTypes:
		return PasswordMediumStrength
	case ThreeCharTypes, FourCharTypes:
		return PasswordHighStrength
	default:
		return PasswordLowStrength
	}
}

// isCommonPassword checks if a password is in our list of common passwords
// This separate function avoids direct reference to the password in logs or error messages
func isCommonPassword(password string) bool {
	// Check both full password and its parts
	if commonPasswords[strings.ToLower(password)] {
		return true
	}

	// Check password parts
	for commonPass := range commonPasswords {
		if strings.Contains(strings.ToLower(password), commonPass) {
			return true
		}
	}

	return false
}

// IsPasswordBreached checks if a password is in a known breach database
// This is a placeholder that should be replaced with an actual API call to Pwned Passwords or similar service
func IsPasswordBreached(password string) (bool, error) {
	// For actual implementation, integrate with haveibeenpwned API or self-hosted pwned passwords database
	// Example API: https://haveibeenpwned.com/API/v3

	// This is a simplified implementation that just checks against our common passwords list
	return isCommonPassword(password), nil
}

// SuggestPasswordImprovement provides suggestions to improve password strength
func SuggestPasswordImprovement(password string) []string {
	var suggestions []string

	if len(password) < PasswordMinLength {
		suggestions = append(suggestions, fmt.Sprintf("Increase password length to at least %d characters", PasswordMinLength))
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		suggestions = append(suggestions, "Add uppercase letters")
	}

	if !hasLower {
		suggestions = append(suggestions, "Add lowercase letters")
	}

	if !hasDigit {
		suggestions = append(suggestions, "Add numbers")
	}

	if !hasSpecial {
		suggestions = append(suggestions, "Add special characters (e.g., !@#$%^&*)")
	}

	if len(password) < PasswordRecommendedLength {
		suggestions = append(suggestions, "Consider using a longer passphrase for better security")
	}

	return suggestions
}
