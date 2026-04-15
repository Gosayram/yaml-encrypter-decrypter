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

	normalized := KeyDerivationAlgorithm(strings.ToLower(strings.TrimSpace(algorithm)))
	if !isSupportedKeyDerivationAlgorithm(normalized) {
		return "", fmt.Errorf("error: invalid algorithm '%s'. Valid options are: argon2id, pbkdf2-sha256, pbkdf2-sha512", algorithm)
	}
	return normalized, nil
}

// GetAvailableAlgorithms returns a list of available key derivation algorithms
func GetAvailableAlgorithms() []string {
	algorithms := GetAvailableKeyDerivationAlgorithms()
	result := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		result = append(result, string(algorithm))
	}
	return result
}
