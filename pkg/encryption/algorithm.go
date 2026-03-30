package encryption

import (
	"fmt"
	"strings"
)

// ValidateAlgorithm validates the algorithm string and returns the corresponding KeyDerivationAlgorithm
func ValidateAlgorithm(algorithm string) (KeyDerivationAlgorithm, error) {
	if algorithm == "" {
		return getDefaultAlgorithm(), nil
	}

	switch strings.ToLower(algorithm) {
	case "argon2id":
		return Argon2idAlgorithm, nil
	case "pbkdf2-sha256":
		return PBKDF2SHA256Algorithm, nil
	case "pbkdf2-sha512":
		return PBKDF2SHA512Algorithm, nil
	default:
		return "", fmt.Errorf("error: invalid algorithm '%s'. Valid options are: argon2id, pbkdf2-sha256, pbkdf2-sha512", algorithm)
	}
}

// GetAvailableAlgorithms returns a list of available key derivation algorithms
func GetAvailableAlgorithms() []string {
	return []string{
		"argon2id",
		"pbkdf2-sha256",
		"pbkdf2-sha512",
	}
}
