// Package main provides the YAML encrypter/decrypter CLI application.
package main

import (
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
)

var (
	// DefaultAlgorithm is the default key derivation algorithm
	DefaultAlgorithm = encryption.Argon2idAlgorithm
)
