package processor

import (
	"strconv"
	"strings"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/encryption"
	"gopkg.in/yaml.v3"
)

// MultilineStyle represents different YAML multiline styles
type MultilineStyle int

const (
	// NotMultiline indicates a regular scalar node
	NotMultiline MultilineStyle = iota
	// LiteralStyle represents the literal style (|)
	LiteralStyle
	// FoldedStyle represents the folded style (>)
	FoldedStyle
)

// Constants for various tags
const (
	// TagInt is the YAML tag for integer values
	TagInt = "!!int"
	// TagStr is the YAML tag for string values
	TagStr = "!!str"
)

// Style suffix constants
const (
	// LiteralStyleSuffix is the suffix for literal style preservation
	LiteralStyleSuffix = "|literal"
	// FoldedStyleSuffix is the suffix for folded style preservation
	FoldedStyleSuffix = "|folded"
	// DoubleQuotedStyleSuffix is the suffix for double-quoted style preservation
	DoubleQuotedStyleSuffix = "|double_quoted"
	// SingleQuotedStyleSuffix is the suffix for single-quoted style preservation
	SingleQuotedStyleSuffix = "|single_quoted"
	// PlainStyleSuffix is the suffix for plain style preservation
	PlainStyleSuffix = "|plain"
)

// Constants for configuration file detection
const (
	// MinConfigLines is the minimum number of lines for a configuration file
	MinConfigLines = 2
	// MinIndentedLines is the minimum number of indented lines for a configuration file
	MinIndentedLines = 1
	// MinDirectives is the minimum number of directives for a configuration file
	MinDirectives = 2
)

// ConfigFilePatterns contains patterns that indicate configuration file content
var ConfigFilePatterns = []string{
	"server {", "location", "http {", // Nginx patterns
	"<VirtualHost", "<Directory", "<Location", // Apache patterns
	"upstream", "proxy_pass", // Common proxy patterns
	"listen", "server_name", // Common server patterns
	"worker_processes", "worker_connections", // Process/connection settings
	"root", "index", // Common web server directives
}

// isConfigurationContent checks if a string contains configuration file patterns
func isConfigurationContent(content string) bool {
	// Skip empty content
	if len(content) == 0 {
		return false
	}

	// Check for common configuration patterns
	for _, pattern := range ConfigFilePatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	// Additional heuristics for configuration files
	lines := strings.Split(content, "\n")
	if len(lines) > MinConfigLines {
		indentedLines := 0
		directiveCount := 0

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) == 0 {
				continue
			}

			// Count indented lines
			if len(line) > len(trimmed) {
				indentedLines++
			}

			// Count lines that look like directives (key value pairs)
			if strings.Contains(trimmed, " ") && !strings.HasPrefix(trimmed, "#") {
				directiveCount++
			}
		}

		// If we have multiple indented lines and directives, it's likely a config file
		return indentedLines > MinIndentedLines && directiveCount > MinDirectives
	}

	return false
}

// DetectMultilineStyle detects the multiline style of a YAML node
func DetectMultilineStyle(node *yaml.Node) MultilineStyle {
	if node == nil || node.Kind != yaml.ScalarNode {
		return NotMultiline
	}

	// Check for literal style (|)
	if node.Style == yaml.LiteralStyle {
		return LiteralStyle
	}

	// Check for folded style (>)
	if node.Style == yaml.FoldedStyle {
		return FoldedStyle
	}

	return NotMultiline
}

// EncryptMultiline encrypts a multiline scalar node while preserving its original style
func EncryptMultiline(node *yaml.Node, key string, debug bool) error {
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}

	// Store the original style and tag
	originalStyle := node.Style
	originalTag := node.Tag

	// Add debug log
	debugLog(debug, "Encrypting node with style %v", originalStyle)

	// Special handling for double-quoted text to preserve escaped new lines
	nodeValue := node.Value
	if originalStyle == yaml.DoubleQuotedStyle {
		nodeValue = preserveQuotedText(nodeValue, originalStyle)
	}

	// Encrypt the value
	encryptedValue, err := encryption.Encrypt(key, nodeValue)
	if err != nil {
		return err
	}

	// Add style suffix to preserve original style information
	var styleSuffix string
	switch originalStyle {
	case yaml.LiteralStyle:
		styleSuffix = LiteralStyleSuffix
	case yaml.FoldedStyle:
		styleSuffix = FoldedStyleSuffix
	case yaml.DoubleQuotedStyle:
		styleSuffix = DoubleQuotedStyleSuffix
	case yaml.SingleQuotedStyle:
		styleSuffix = SingleQuotedStyleSuffix
	default:
		styleSuffix = PlainStyleSuffix
	}

	// Set the encrypted value with the AES prefix and style suffix
	node.Value = AES + encryptedValue + styleSuffix

	// Reset the style to plain to avoid YAML formatting issues
	node.Style = 0

	// Clear the tag if it's !!int, otherwise keep the original tag
	if originalTag == TagInt {
		node.Tag = "" // Remove !!int tag to avoid explicit type in output
	}

	debugLog(debug, "Encrypted node with style: %v", originalStyle)
	return nil
}

// DecryptMultiline decrypts a multiline scalar node and restores its original style
func DecryptMultiline(node *yaml.Node, decryptFn func(string) (string, error)) error {
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}

	// Skip decryption if the node doesn't have an AES prefix
	if !strings.HasPrefix(node.Value, AES) {
		return nil
	}

	// Extract the encrypted value (skipping the AES marker) and handle style suffix
	encryptedValue := strings.TrimPrefix(node.Value, AES)

	// Check for style suffix
	var styleSuffix string
	styleInfo := yaml.Style(0) // Default plain style

	// Extract style suffix if present
	lastPipeIndex := strings.LastIndex(encryptedValue, "|")
	if lastPipeIndex != -1 && lastPipeIndex < len(encryptedValue)-1 {
		styleSuffix = encryptedValue[lastPipeIndex+1:]
		encryptedValue = encryptedValue[:lastPipeIndex]

		// Convert style suffix to yaml.Style
		switch styleSuffix {
		case StyleLiteral:
			styleInfo = yaml.LiteralStyle
		case StyleFolded:
			styleInfo = yaml.FoldedStyle
		case StyleDoubleQuoted:
			styleInfo = yaml.DoubleQuotedStyle
		case StyleSingleQuoted:
			styleInfo = yaml.SingleQuotedStyle
		case StylePlain:
			styleInfo = yaml.Style(0) // Plain style (default)
		}
	}

	// Decrypt the value using the provided decryption function
	decryptedValue, err := decryptFn(AES + encryptedValue)
	if err != nil {
		return err
	}

	// Update the node value with the decrypted value
	node.Value = decryptedValue

	// Apply the original style from the style suffix
	if styleSuffix != "" {
		node.Style = styleInfo
	}

	// Determine if the value is numeric and handle tag appropriately
	if isNumeric(decryptedValue) {
		node.Tag = ""
	}

	return nil
}

// IsMultilineContent checks if a string contains newlines
func IsMultilineContent(content string) bool {
	return strings.Contains(content, "\n")
}

// ProcessMultilineNode processes scalar nodes with style-aware handling for
// encryption and decryption (including multiline and quoted text variants).
func ProcessMultilineNode(node *yaml.Node, path string, key, operation string, debug bool) (bool, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false, nil
	}

	debugLog(debug, "Processing node at path %s with style %v", path, node.Style)

	// Only process nodes that need encryption/decryption
	switch operation {
	case OperationEncrypt:
		// For encryption, only encrypt the node if it's not already encrypted
		if !strings.HasPrefix(node.Value, AES) {
			// Encrypt the node
			if err := EncryptMultiline(node, key, debug); err != nil {
				return false, err
			}
			return true, nil
		}
	case OperationDecrypt:
		// For decryption, only decrypt if the node has the AES prefix
		if strings.HasPrefix(node.Value, AES) {
			// Create a decryption function that uses the key
			decryptFn := func(value string) (string, error) {
				// Strip AES prefix
				encrypted := strings.TrimPrefix(value, AES)

				// Decrypt using the encryption package
				decryptedBuffer, err := encryption.DecryptToString(encrypted, key)
				if err != nil {
					return "", err
				}
				return decryptedBuffer, nil
			}

			// Decrypt the node
			if err := DecryptMultiline(node, decryptFn); err != nil {
				return false, err
			}
			return true, nil
		}
	}

	return false, nil
}

// DecryptValue decrypts an AES-prefixed value
func DecryptValue(value string, key string) (string, error) {
	// If not encrypted, return as is
	if !strings.HasPrefix(value, AES) {
		return value, nil
	}

	// Strip the AES prefix and decrypt
	encrypted := strings.TrimPrefix(value, AES)

	decryptedBuffer, err := encryption.DecryptToString(encrypted, key)
	if err != nil {
		return "", err
	}

	return decryptedBuffer, nil
}

// isNumeric checks if a string represents a numeric value.
// This is important for YAML processing because numeric values have different tags (!!int, !!float)
// than string values. When a numeric value is encrypted/decrypted, we need to ensure proper
// type information is preserved.
//
// Parameters:
//   - s: The string to check
//
// Returns:
//   - bool: True if the string represents a valid numeric value, false otherwise
func isNumeric(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// preserveQuotedText processes special characters in quoted text
// so that they are correctly preserved during encryption
//
// Parameters:
//   - text: source text to process
//   - style: YAML text style
//
// Returns:
//   - string: processed text with preserved escaped characters
func preserveQuotedText(text string, style yaml.Style) string {
	if style != yaml.DoubleQuotedStyle {
		return text
	}

	// For text in double quotes, we need to preserve escaped characters
	// This is especially important for \n, \t, \r, etc.
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
		text, "\\n", "\n"), "\\t", "\t"), "\\r", "\r")
}
