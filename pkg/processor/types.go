package processor

import (
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
)

// File contains constants and variables for YAML file processing
const (
	// Operations
	AES              = "AES256:"
	OperationEncrypt = "encrypt"
	OperationDecrypt = "decrypt"

	// Buffer and processing constants
	DefaultBufferSize    = 1024
	DefaultIndent        = 2
	LargeFileThreshold   = 1000
	MaxParts             = 2
	MaskLength           = 6
	MinKeyLength         = 15 // Minimum length for encryption key (NIST SP 800-63B)
	MinKeyLengthStandard = 20 // Minimum length for encryption key in standard processor
	minKeyLengthGuard    = 8  // Guardrail for obviously weak keys before KDF validation
	Base64BlockSize      = 4  // Block size for Base64 encoding

	// Base64 padding constants
	Base64NoPadding     = 0 // If length % 4 == 0, no padding needed
	Base64InvalidPad    = 1 // If length % 4 == 1, this is an invalid Base64 string
	Base64DoublePadding = 2 // If length % 4 == 2, need to add two '==' characters
	Base64SinglePadding = 3 // If length % 4 == 3, need to add one '=' character

	// Action types
	ActionNone    = "none"
	ActionEncrypt = "encrypt"

	// Magic numbers
	MinEncryptedLength = 6
	KeyValuePairSize   = 2

	// File permissions
	SecureFileMode = 0600 // Secure file permissions (owner read/write only)

	// Masked value for sensitive information
	MaskedValue = "********"

	// EncryptedPrefix is the prefix for encrypted values
	EncryptedPrefix = "AES256:"

	// AlgorithmIndicatorLength is the length of the algorithm indicator
	AlgorithmIndicatorLength = 16

	// Additional YAML node style names (for style suffixes)
	StyleLiteral      = "literal"
	StyleFolded       = "folded"
	StyleDoubleQuoted = "double_quoted"
	StyleSingleQuoted = "single_quoted"
	StylePlain        = "plain"

	// Constants for parsing YAML files
	YAMLIndentSpaces = 2

	// YAML tag for string
	YAMLTagStr = "!!str"

	// Constants for masking encryption keys
	minKeyLengthToShow    = 4  // Minimum key length for display
	minKeyLength          = 6  // Minimum key length for fields
	previewEncryptedChars = 20 // Number of characters to display for encrypted text
	previewNodeChars      = 30 // Number of characters to display for node value

	// UnknownAlgorithm is the constant for unknown algorithm
	UnknownAlgorithm = "unknown algorithm"
	matchStatusNo    = "does not match"
	matchStatusOK    = "matches"

	// Constants for YAML structure
	linesPerRule = 6
	// First rule starts after "encryption:" and "rules:"
	firstRuleOffset = 5
	// RangeRegexMatchCount is the expected number of matches for range regex
	RangeRegexMatchCount = 3
)

type Rule struct {
	Name        string `yaml:"name"`
	Block       string `yaml:"block"`   // Block to which the rule applies (e.g., "smart_config" or "*")
	Pattern     string `yaml:"pattern"` // Pattern for searching fields within the block (e.g., "**" or "pass*")
	Exclude     string `yaml:"exclude,omitempty"`
	Action      string `yaml:"action,omitempty"` // Default will be "encrypt"
	Description string `yaml:"description"`
}

// Config contains settings for YAML processing
type Config struct {
	Encryption struct {
		Rules         []Rule   `yaml:"rules"`
		UnsecureDiff  bool     `yaml:"unsecure_diff"`
		IncludeRules  []string `yaml:"include_rules,omitempty"`  // Paths to additional rule files
		ValidateRules *bool    `yaml:"validate_rules,omitempty"` // Whether to validate rules (default: true)
	} `yaml:"encryption"`
	Key          string
	Operation    string
	Debug        bool
	UnsecureDiff bool
}

// Structure to hold information about folded style sections
type FoldedStyleSection struct {
	Key         string
	IndentLevel int
	Content     string
}

// KeyDerivationAlgorithm is an alias for encryption.KeyDerivationAlgorithm
type KeyDerivationAlgorithm = encryption.KeyDerivationAlgorithm
