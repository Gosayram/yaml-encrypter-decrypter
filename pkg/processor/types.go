package processor

import (
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
)

// File contains constants and variables for YAML file processing
const (
	// AES is the prefix for AES-256 encrypted values
	AES = "AES256:"
	// OperationEncrypt is the encryption operation constant
	OperationEncrypt = "encrypt"
	// OperationDecrypt is the decryption operation constant
	OperationDecrypt = "decrypt"

	// DefaultBufferSize is the default buffer size for I/O operations
	DefaultBufferSize = 1024
	// DefaultIndent is the default YAML indentation in spaces
	DefaultIndent = 2
	// LargeFileThreshold is the threshold in lines for large file processing
	LargeFileThreshold = 1000
	// MaxParts is the maximum number of parts for path splitting
	MaxParts = 2
	// MaskLength is the length of the mask for sensitive values
	MaskLength           = 6
	MinKeyLength         = 15 // Minimum length for encryption key (NIST SP 800-63B)
	MinKeyLengthStandard = 20 // Minimum length for encryption key in standard processor
	minKeyLengthGuard    = 8  // Guardrail for obviously weak keys before KDF validation
	Base64BlockSize      = 4  // Block size for Base64 encoding

	// Base64NoPadding indicates no padding is needed for Base64
	Base64NoPadding = 0
	// Base64InvalidPad indicates invalid Base64 padding
	Base64InvalidPad = 1
	// Base64DoublePadding indicates double padding is needed for Base64
	Base64DoublePadding = 2
	// Base64SinglePadding indicates single padding is needed for Base64
	Base64SinglePadding = 3

	// ActionNone is the none action constant
	ActionNone = "none"
	// ActionEncrypt is the encrypt action constant
	ActionEncrypt = "encrypt"

	// MinEncryptedLength is the minimum length for encrypted values
	MinEncryptedLength = 6
	// KeyValuePairSize is the size of a key-value pair
	KeyValuePairSize = 2

	// SecureFileMode is the secure file permission mode (owner read/write only)
	SecureFileMode = 0600

	// MaskedValue is the string used to mask sensitive information
	MaskedValue = "********"

	// EncryptedPrefix is the prefix for encrypted values
	EncryptedPrefix = "AES256:"

	// AlgorithmIndicatorLength is the length of the algorithm indicator
	AlgorithmIndicatorLength = 16

	// StyleLiteral is the literal style name
	StyleLiteral = "literal"
	// StyleFolded is the folded style name
	StyleFolded = "folded"
	// StyleDoubleQuoted is the double-quoted style name
	StyleDoubleQuoted = "double_quoted"
	// StyleSingleQuoted is the single-quoted style name
	StyleSingleQuoted = "single_quoted"
	// StylePlain is the plain style name
	StylePlain = "plain"

	// YAMLIndentSpaces is the number of spaces for YAML indentation
	YAMLIndentSpaces = 2

	// YAMLTagStr is the YAML tag for string type
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

// FoldedStyleSection holds information about folded style sections in YAML
type FoldedStyleSection struct {
	Key         string
	IndentLevel int
	Content     string
}

// KeyDerivationAlgorithm is an alias for encryption.KeyDerivationAlgorithm
type KeyDerivationAlgorithm = encryption.KeyDerivationAlgorithm
