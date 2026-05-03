// Package processor provides YAML encryption and decryption capabilities.
//
// It supports encrypting and decrypting YAML files using AES-256 encryption,
// with rule-based configuration to selectively encrypt specific fields.
//
// Key features:
//   - Rule-based encryption/decryption based on YAML paths
//   - Preservation of YAML formatting and style (literal, folded, quoted)
//   - Support for multiline content (PEM certificates, configuration files)
//   - Diff output with masking of sensitive values
//   - Configurable exclusion rules
//
// Usage:
//
//	// Load rules from config
//	rules, config, err := processor.LoadRules("config.yml", false)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Process a file
//	err = processor.ProcessFile("secrets.yml", config.Key, processor.OperationEncrypt, false, "config.yml")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Rule configuration:
//
//	encryption:
//	  rules:
//	    - name: encrypt passwords
//	      block: users
//	      pattern: password
//	      action: encrypt
//	    - name: skip public keys
//	      block: users
//	      pattern: public_key
//	      action: none
//
// The package follows Go best practices including:
//   - Minimal global state (encapsulated in config structs)
//   - Interface-based design for testability
//   - Custom error types for better error handling
//   - Go 1.25+ features (sync.WaitGroup.Go, etc.)
package processor
