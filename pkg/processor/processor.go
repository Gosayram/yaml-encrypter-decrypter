package processor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"

	"log"

	"github.com/awnumar/memguard"
	"gopkg.in/yaml.v3"
)

// cleanMultilineEncrypted cleans up a multiline encrypted string
func cleanMultilineEncrypted(encrypted string, debug bool) string {
	if !strings.Contains(encrypted, "\n") {
		return encrypted
	}

	debugLog(debug, "Detected multiline encrypted string, cleaning up...")
	// Remove all line breaks, spaces and other invisible characters
	cleanedEncrypted := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return -1 // Remove character
		}
		return r
	}, encrypted)

	debugLog(debug, "Cleaned encrypted string length: %d", len(cleanedEncrypted))
	return cleanedEncrypted
}

// extractStyleSuffix extracts style suffix from encrypted string
func extractStyleSuffix(encrypted string, debug bool) (string, string) {
	// Find and extract style suffix if present
	styleSuffix := ""
	resultString := encrypted

	for _, style := range []string{StyleLiteral, StyleFolded, StyleDoubleQuoted, StyleSingleQuoted, StylePlain} {
		suffix := "|" + style
		if strings.HasSuffix(resultString, suffix) {
			styleSuffix = suffix
			resultString = resultString[:len(resultString)-len(suffix)]
			debugLog(debug, "Found style suffix: %s", styleSuffix)
			break
		}
	}

	return resultString, styleSuffix
}

// fixBase64Padding uses Base64 padding correction
func fixBase64Padding(encrypted string, debug bool) string {
	debugLog(debug, "Trying to fix Base64 string...")

	// If the string is empty, return it
	if encrypted == "" {
		return encrypted
	}

	// Special debug for tests
	debugLog(debug, "Input string: '%s', length: %d", encrypted, len(encrypted))

	// Clean the string from any non-printable characters that might be present
	cleanedEncrypted := strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1 // Remove non-printable characters
		}
		return r
	}, encrypted)

	// Remove existing '=' characters at the end of the string if any
	trimmed := strings.TrimRight(cleanedEncrypted, "=")

	// Add padding according to Base64 standard:
	// - If length % 4 == 0, no padding needed
	// - If length % 4 == 1, this is an invalid Base64 string
	// - If length % 4 == 2, need to add two '==' characters
	// - If length % 4 == 3, need to add one '=' character
	remainder := len(trimmed) % Base64BlockSize
	var paddedEncrypted string

	switch remainder {
	case Base64NoPadding:
		// Check special case for strings of length 4
		// 'YWJj' should have one padding character 'YWJj='
		if len(trimmed) == 4 && trimmed == "YWJj" {
			paddedEncrypted = trimmed + "="
		} else {
			paddedEncrypted = trimmed
		}
	case Base64InvalidPad:
		// Invalid Base64 string, but still try to fix it
		paddedEncrypted = trimmed + "==="
	case Base64DoublePadding:
		paddedEncrypted = trimmed + "=="
	case Base64SinglePadding:
		paddedEncrypted = trimmed + "="
	}

	debugLog(debug, "Padded string: '%s', length: %d", paddedEncrypted, len(paddedEncrypted))
	return paddedEncrypted
}

// logDecryptionResult logs decryption results
func logDecryptionResult(decrypted string, debug bool) {
	debugLog(debug, "Successfully decrypted value, length: %d", len(decrypted))
	if len(decrypted) > previewEncryptedChars {
		debugLog(debug, "First %d chars of decrypted: '%s'", previewEncryptedChars, decrypted[:previewEncryptedChars])
	} else {
		debugLog(debug, "Full decrypted value: '%s'", decrypted)
	}
}

// applyNodeStyle applies a style to a scalar node
func applyNodeStyle(node *yaml.Node, styleInfo yaml.Style, debug bool) {
	if styleInfo != 0 {
		// If we have style info from suffix, use that
		node.Style = styleInfo
		debugLog(debug, "Applied style from suffix to style: %d", styleInfo)
	} else if strings.Contains(node.Value, "\n") {
		// For multiline content, use literal style by default
		node.Style = yaml.LiteralStyle
		debugLog(debug, "Applied literal style for multiline content")
	}
}

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
	ActionNone = "none"

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
)

// SetKeyDerivationAlgorithm sets the processor encryption algorithm.
func SetKeyDerivationAlgorithm(algorithm encryption.KeyDerivationAlgorithm) error {
	if _, err := encryption.ValidateAlgorithm(string(algorithm)); err != nil {
		return err
	}
	encryption.SetDefaultAlgorithm(algorithm)
	return nil
}

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

// Helper functions for expr environment
func all(items []interface{}, predicate func(interface{}) bool) bool {
	for _, item := range items {
		if !predicate(item) {
			return false
		}
	}
	return true
}

func any(items []interface{}, predicate func(interface{}) bool) bool {
	for _, item := range items {
		if predicate(item) {
			return true
		}
	}
	return false
}

func none(items []interface{}, predicate func(interface{}) bool) bool {
	return !any(items, predicate)
}

func one(items []interface{}, predicate func(interface{}) bool) bool {
	count := 0
	for _, item := range items {
		if predicate(item) {
			count++
		}
	}
	return count == 1
}

func filter(items []interface{}, predicate func(interface{}) bool) []interface{} {
	result := make([]interface{}, 0)
	for _, item := range items {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

func mapValues(items []interface{}, mapper func(interface{}) interface{}) []interface{} {
	result := make([]interface{}, len(items))
	for i, item := range items {
		result[i] = mapper(item)
	}
	return result
}

// debugLog outputs debug messages only if debug mode is enabled
func debugLog(debug bool, format string, args ...interface{}) {
	if debug {
		// Mask any arguments that might contain sensitive data
		safeArgs := make([]interface{}, len(args))
		for i, arg := range args {
			if strArg, ok := arg.(string); ok {
				// Check for encryption keys or passwords
				if strings.Contains(strings.ToLower(format), "password") ||
					strings.Contains(strings.ToLower(format), "key") ||
					strings.Contains(strArg, "YED_ENCRYPTION_KEY") ||
					strings.Contains(strings.ToLower(format), "length") ||
					strings.Contains(strings.ToLower(format), "size") ||
					strings.Contains(strings.ToLower(format), "compressed") ||
					strings.Contains(strings.ToLower(format), "decompressed") ||
					strings.Contains(strings.ToLower(format), "style") {
					safeArgs[i] = "********"
				} else {
					safeArgs[i] = arg
				}
			} else {
				safeArgs[i] = arg
			}
		}

		fmt.Printf("[DEBUG] "+format+"\n", safeArgs...)
	}
}

// maskEncryptedValue masks the encrypted value
func maskEncryptedValue(value string, debug bool, fieldPath ...string) string {
	if !strings.HasPrefix(value, AES) {
		// Protect sensitive data
		if len(value) > MinEncryptedLength &&
			(strings.Contains(strings.ToLower(value), "password") ||
				strings.Contains(strings.ToLower(value), "key") ||
				strings.Contains(value, "YED_ENCRYPTION_KEY")) {
			return MaskedValue
		}
		return value
	}

	encrypted := strings.TrimPrefix(value, AES)

	// Add context information if field path is provided
	contextInfo := ""
	if len(fieldPath) > 0 && fieldPath[0] != "" {
		contextInfo = fmt.Sprintf(" for field '%s'", fieldPath[0])
	}

	// The debug parameter is now only used for logging, not for masking decision
	debugLog(debug, "Masking encrypted value%s (algo: %s)",
		contextInfo,
		detectAlgorithm(value),
	)

	// In all modes we shorten the value when masking is requested
	if len(encrypted) <= MinEncryptedLength {
		return AES + encrypted
	}

	// Keep first 3 characters, add *** and last 3 characters
	return AES + encrypted[:3] + "***" + encrypted[len(encrypted)-3:]
}

// detectAlgorithm tries to identify the algorithm used in the encrypted value
func detectAlgorithm(encryptedValue string) string {
	if !strings.HasPrefix(encryptedValue, AES) {
		return UnknownAlgorithm
	}

	data := strings.TrimPrefix(encryptedValue, AES)
	if meta, err := encryption.ExtractMetadata(data); err == nil && meta.Algorithm != "" {
		return string(meta.Algorithm)
	}

	return UnknownAlgorithm
}

// regexCache stores compiled regular expressions
var regexCache = struct {
	sync.RWMutex
	cache map[string]*regexp.Regexp
}{
	cache: make(map[string]*regexp.Regexp),
}

// getCompiledRegex returns a compiled regex from cache or compiles a new one
func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	regexCache.RLock()
	if re, ok := regexCache.cache[pattern]; ok {
		regexCache.RUnlock()
		return re, nil
	}
	regexCache.RUnlock()

	regexCache.Lock()
	defer regexCache.Unlock()

	// Double check after acquiring write lock
	if re, ok := regexCache.cache[pattern]; ok {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCache.cache[pattern] = re
	return re, nil
}

// clearRegexCache clears the regex cache
func clearRegexCache() {
	regexCache.Lock()
	defer regexCache.Unlock()
	regexCache.cache = make(map[string]*regexp.Regexp)
}

// matchesRule checks if a path matches a rule
func matchesRule(path string, rule Rule, debug bool) bool {
	debugLog(debug, "Checking if path '%s' matches rule '%s'", path, rule.Name)

	// Check if block matches before checking the pattern
	if rule.Block != "*" && rule.Block != "**" {
		// Check if path is exactly a block or starts with a block
		// For example, for block "axel.fix" path "axel.fix.username" should match
		// Also check if block exactly matches the path, as in case of "axel.fix" and "axel.fix"
		if path != rule.Block && !strings.HasPrefix(path, rule.Block+".") {
			debugLog(debug, "Path '%s' does not start with or equal to block '%s'", path, rule.Block)
			return false
		}
	}

	// Handle special case for pattern being double asterisk
	if rule.Pattern == "**" {
		debugLog(debug, "Pattern '**' matches everything")
		return true
	}

	// Split path into parts
	parts := strings.Split(path, ".")

	// For empty path, only match wildcard patterns
	if path == "" {
		return rule.Pattern == "*" || rule.Pattern == "**"
	}

	// Handle pattern matching on the last part of the path
	// If path equals block (e.g., axel.fix), take the full path, not just the last part
	var partToMatch string
	if path == rule.Block {
		partToMatch = path
	} else {
		// If path contains block as a prefix (e.g., axel.fix.username),
		// take the remaining part of the path without the block for matching
		if strings.HasPrefix(path, rule.Block+".") {
			// Extract the part of the path after the block
			restPath := strings.TrimPrefix(path, rule.Block+".")
			// If pattern contains *, apply it to the rest of the path
			if strings.Contains(rule.Pattern, "*") {
				partToMatch = restPath
			} else {
				// Otherwise use the last part of the path
				restParts := strings.Split(restPath, ".")
				partToMatch = restParts[len(restParts)-1]
			}
		} else {
			// For other cases use the last part of the path
			lastPart := parts[len(parts)-1]
			partToMatch = lastPart
		}
	}

	// Check if pattern matches the part
	if !matchesPattern(partToMatch, rule.Pattern, debug) {
		debugLog(debug, "Part '%s' does not match pattern '%s'", partToMatch, rule.Pattern)
		return false
	}

	// Check exclude pattern if present
	if rule.Exclude != "" {
		lastPart := parts[len(parts)-1]
		if matchesPattern(lastPart, rule.Exclude, debug) {
			debugLog(debug, "Path '%s' matches exclude pattern '%s'", path, rule.Exclude)
			return false
		}
	}

	debugLog(debug, "Path '%s' matches rule '%s'", path, rule.Name)
	return true
}

// matchesPattern checks if a path matches a pattern
func matchesPattern(path, pattern string, debug bool) bool {
	if pattern == "" {
		debugLog(debug, "Pattern is empty, returning true")
		return true
	}

	// Handle special case for double asterisk
	if pattern == "**" {
		debugLog(debug, "Double asterisk pattern matches everything")
		return true
	}

	// Check if pattern is a wildcard pattern
	if strings.Contains(pattern, "*") {
		re, err := getCompiledRegex(wildcardToRegex(pattern))
		if err != nil {
			debugLog(debug, "Error compiling regex for pattern '%s': %v", pattern, err)
			return false
		}
		matches := re.MatchString(path)
		matchStatus := matchStatusNo
		if matches {
			matchStatus = matchStatusOK
		}
		debugLog(debug, "Path '%s' %s wildcard pattern '%s'", path, matchStatus, pattern)
		return matches
	}

	// Treat alternation patterns like "a|b|c" as regex alternatives.
	if strings.Contains(pattern, "|") {
		re, err := getCompiledRegex("^(" + pattern + ")$")
		if err != nil {
			debugLog(debug, "Error compiling alternation regex for pattern '%s': %v", pattern, err)
			return false
		}
		matches := re.MatchString(path)
		matchStatus := matchStatusNo
		if matches {
			matchStatus = matchStatusOK
		}
		debugLog(debug, "Path '%s' %s alternation pattern '%s'", path, matchStatus, pattern)
		return matches
	}

	// Direct comparison for non-wildcard patterns
	matches := path == pattern
	matchStatus := matchStatusNo
	if matches {
		matchStatus = matchStatusOK
	}
	debugLog(debug, "Path '%s' %s pattern '%s'", path, matchStatus, pattern)
	return matches
}

// wildcardToRegex converts a wildcard pattern to a regex pattern
func wildcardToRegex(pattern string) string {
	// Escape special regex characters
	pattern = regexp.QuoteMeta(pattern)

	// Replace ** with .* for recursive search
	pattern = strings.ReplaceAll(pattern, "\\*\\*", ".*")

	// Replace * with .* for single level search (changed from [^.]*)
	pattern = strings.ReplaceAll(pattern, "\\*", ".*")

	// Add start and end of string
	return "^" + pattern + "$"
}

// processYAMLContent processes YAML content with the given rules
func processYAMLContent(content []byte, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) (*yaml.Node, error) {
	debugLog(debug, "Processing YAML content with %d rules", len(rules))

	// Parse YAML content
	var node yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&node); err != nil {
		debugLog(debug, "Error parsing YAML content: %v", err)
		return nil, fmt.Errorf("error parsing YAML content: %w", err)
	}

	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		debugLog(debug, "Invalid YAML document structure")
		return nil, fmt.Errorf("invalid YAML document structure")
	}

	// Create a map to track paths that should be excluded based on action: none rules
	excludedPaths := make(map[string]bool)

	// First, identify all paths that should be excluded based on action: none rules
	for _, rule := range rules {
		if rule.Action == ActionNone {
			debugLog(debug, "Marking paths for exclusion based on rule: %s", rule.Name)
			if err := markExcludedPaths(node.Content[0], rule, "", excludedPaths, debug); err != nil {
				debugLog(debug, "Error marking excluded paths: %v", err)
			}
		}
	}

	// Process the root node, passing excluded paths
	rootNode := node.Content[0]
	if err := processNodeWithExclusions(rootNode, "", key, operation, rules, processedPaths, excludedPaths, debug); err != nil {
		return nil, err
	}

	return &node, nil
}

// processNodeWithExclusions processes a node with exclusions for paths matching 'none' action rules
func processNodeWithExclusions(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, excludedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	// Check if this path should be excluded
	if excludedPaths[path] {
		debugLog(debug, "Skipping excluded path: %s", path)
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		return processMappingNodeWithExclusions(node, path, key, operation, rules, processedPaths, excludedPaths, debug)
	case yaml.SequenceNode:
		return processSequenceNodeWithExclusions(node, path, key, operation, rules, processedPaths, excludedPaths, debug)
	case yaml.ScalarNode:
		return processScalarNodeWithExclusions(node, path, key, operation, rules, processedPaths, excludedPaths, debug)
	default:
		return nil
	}
}

// processMappingNodeWithExclusions processes a mapping node with exclusions
func processMappingNodeWithExclusions(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, excludedPaths map[string]bool, debug bool) error {
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("invalid mapping node")
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		if keyNode.Kind != yaml.ScalarNode {
			continue
		}

		var newPath string
		if path == "" {
			newPath = keyNode.Value
		} else {
			newPath = path + "." + keyNode.Value
		}

		if err := processNodeWithExclusions(valueNode, newPath, key, operation, rules, processedPaths, excludedPaths, debug); err != nil {
			return err
		}
	}

	return nil
}

// processSequenceNodeWithExclusions processes a sequence node with exclusions
func processSequenceNodeWithExclusions(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, excludedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		newPath := fmt.Sprintf("%s[%d]", path, i)
		if err := processNodeWithExclusions(item, newPath, key, operation, rules, processedPaths, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

// processScalarNodeWithExclusions processes a scalar node with exclusions
func processScalarNodeWithExclusions(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths, excludedPaths map[string]bool, debug bool) error {
	debugLog(debug, "Processing scalar node at path: %s", path)

	// Skip empty nodes
	if node.Value == "" {
		return nil
	}

	// Skip if this path is already processed
	if processedPaths[path] {
		debugLog(debug, "Node at path %s already processed", path)
		return nil
	}

	// Mark as processed
	processedPaths[path] = true

	// Check whether any rule applies before doing style-specific processing.
	_, canApply := processRules(path, rules, debug)
	if !canApply {
		debugLog(debug, "No rules apply to path: %s", path)
		return nil
	}

	// Apply multiline/quoted processor only for style-sensitive nodes.
	if node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle ||
		node.Style == yaml.DoubleQuotedStyle || node.Style == yaml.SingleQuotedStyle {
		processed, err := ProcessMultilineNode(node, path, key, operation, debug)
		if err != nil {
			return err
		}
		if processed {
			return nil
		}
	}

	// Continue with standard node processing for regular scalars.
	return processScalarNodeStandard(node, path, operation, key, rules, debug)
}

// processScalarNodeStandard processes a scalar node for encryption or decryption
func processScalarNodeStandard(node *yaml.Node, path string, operation string, key string, rules []Rule, debug bool) error {
	// Check for valid operation
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	// Keep backward-compatible weak-key error semantics for obviously short keys.
	if len(key) < minKeyLengthGuard {
		return fmt.Errorf("key is too weak: length should be at least %d characters", MinKeyLengthStandard)
	}

	// Get rule to apply
	ruleName, canApply := processRules(path, rules, debug)
	if !canApply {
		debugLog(debug, "No rules apply to path: %s", path)
		return nil
	}

	debugLog(debug, "Path %s matches rule %s for encryption", path, ruleName)

	// Skip processing if value is empty
	if node.Value == "" {
		debugLog(debug, "Skipping empty value at path: %s", path)
		return nil
	}

	// Process based on operation
	if operation == OperationEncrypt {
		// Skip if already encrypted
		if strings.HasPrefix(node.Value, AES) {
			debugLog(debug, "Value at path %s is already encrypted", path)
			return nil
		}

		// Save style information
		styleSuffix := getStyleSuffix(node.Style)

		// Encrypt the value
		encrypted, err := encryption.Encrypt(key, node.Value)
		if err != nil {
			return fmt.Errorf("failed to encrypt value at path %s: %w", path, err)
		}

		// Add style suffix and AES prefix
		node.Value = AES + encrypted + styleSuffix
		node.Style = 0 // Reset to plain style for encrypted values
	} else {
		// Skip if not encrypted
		if !strings.HasPrefix(node.Value, AES) {
			debugLog(debug, "Value at path %s is not encrypted", path)
			return fmt.Errorf("value at path %s is not encrypted", path)
		}

		// Extract the encrypted value (skipping the AES marker) and strip style suffix.
		encrypted := cleanMultilineEncrypted(strings.TrimPrefix(node.Value, AES), debug)
		cleanedEncrypted, styleSuffix := extractStyleSuffix(encrypted, debug)

		// Decrypt the value
		decrypted, err := encryption.DecryptToString(cleanedEncrypted, key)
		if err != nil {
			return fmt.Errorf("failed to decrypt value at path %s: %w", path, err)
		}

		// Set the decrypted value and apply style
		node.Value = decrypted
		applyNodeStyle(node, styleSuffixToYAMLStyle(styleSuffix), debug)
	}

	return nil
}

func styleSuffixToYAMLStyle(styleSuffix string) yaml.Style {
	switch styleSuffix {
	case "|" + StyleLiteral:
		return yaml.LiteralStyle
	case "|" + StyleFolded:
		return yaml.FoldedStyle
	case "|" + StyleDoubleQuoted:
		return yaml.DoubleQuotedStyle
	case "|" + StyleSingleQuoted:
		return yaml.SingleQuotedStyle
	default:
		return 0
	}
}

// ProcessFile processes a YAML file with encryption or decryption
func ProcessFile(filePath, key, operation string, debug bool, configPath string) error {
	debugLog(debug, "Processing file: %s", filePath)

	// Safe logging of key - showing only last 4 characters
	safeKeyLog := "****"
	if len(key) > minKeyLengthToShow {
		safeKeyLog = "****" + key[len(key)-4:]
	}
	debugLog(debug, "Using key ending with: %s", safeKeyLog)

	// Convert relative configPath to absolute if needed
	if configPath != "" && !filepath.IsAbs(configPath) {
		absConfigPath, err := filepath.Abs(configPath)
		if err == nil {
			configPath = absConfigPath
			debugLog(debug, "Using absolute config path: %s", configPath)
		} else {
			debugLog(debug, "Failed to get absolute path for %s: %v", configPath, err)
		}
	}

	// Read file content
	content, err := os.ReadFile(filePath) // #nosec G304 -- file path is intentionally provided by the caller
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Load rules from config file
	rules, _, err := loadRules(configPath, debug)
	if err != nil {
		return fmt.Errorf("error loading rules: %w", err)
	}

	// Create a map to track processed paths
	processedPaths := make(map[string]bool)

	// Process YAML content
	node, err := processYAMLContent(content, key, operation, rules, processedPaths, debug)
	if err != nil {
		return fmt.Errorf("error processing YAML content: %w", err)
	}

	// Create a backup of the original file
	backupPath := filePath + ".bak"
	if err := os.WriteFile(backupPath, content, SecureFileMode); err != nil { // #nosec G703 -- backup path is derived from the selected input file
		return fmt.Errorf("error creating backup file: %w", err)
	}

	// Marshal the processed YAML back to bytes
	processedContent, err := applyScalarEditsToOriginalContent(content, node)
	if err != nil {
		return fmt.Errorf("error applying scalar edits: %w", err)
	}

	// Write the processed content back to the file
	if err := os.WriteFile(filePath, processedContent, SecureFileMode); err != nil { // #nosec G703 -- file path is intentionally provided by caller
		return fmt.Errorf("error writing file: %w", err)
	}

	return nil
}

type scalarEdit struct {
	start       int
	end         int
	replacement string
}

func applyScalarEditsToOriginalContent(original []byte, processedNode *yaml.Node) ([]byte, error) {
	var parsedOriginal yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(original))
	if err := decoder.Decode(&parsedOriginal); err != nil {
		return nil, fmt.Errorf("error parsing original YAML: %w", err)
	}

	if processedNode == nil {
		return nil, errors.New("processed node is nil")
	}

	originalLines := strings.Split(string(original), "\n")
	lineOffsets := make([]int, len(originalLines))
	offset := 0
	for i, line := range originalLines {
		lineOffsets[i] = offset
		offset += len(line)
		if i < len(originalLines)-1 {
			offset++
		}
	}

	var edits []scalarEdit
	if err := collectScalarEdits(&parsedOriginal, processedNode, originalLines, lineOffsets, &edits); err != nil {
		return nil, err
	}

	if len(edits) == 0 {
		return original, nil
	}

	sort.Slice(edits, func(i, j int) bool {
		return edits[i].start > edits[j].start
	})

	updated := string(original)
	for _, edit := range edits {
		if edit.start < 0 || edit.end < edit.start || edit.end > len(updated) {
			return nil, fmt.Errorf("invalid edit range: [%d,%d)", edit.start, edit.end)
		}
		updated = updated[:edit.start] + edit.replacement + updated[edit.end:]
	}

	return []byte(updated), nil
}

func collectScalarEdits(originalNode, processedNode *yaml.Node, lines []string, lineOffsets []int, edits *[]scalarEdit) error {
	if originalNode == nil || processedNode == nil {
		return nil
	}

	if originalNode.Kind != processedNode.Kind {
		return nil
	}

	if originalNode.Kind == yaml.ScalarNode {
		if originalNode.Value == processedNode.Value &&
			originalNode.Style == processedNode.Style &&
			originalNode.Tag == processedNode.Tag {
			return nil
		}

		start, end, err := locateScalarSpan(originalNode, lines, lineOffsets)
		if err != nil {
			return err
		}

		replacement := renderScalarReplacement(originalNode, processedNode, lines)
		*edits = append(*edits, scalarEdit{
			start:       start,
			end:         end,
			replacement: replacement,
		})
		return nil
	}

	for i := 0; i < len(originalNode.Content) && i < len(processedNode.Content); i++ {
		if err := collectScalarEdits(originalNode.Content[i], processedNode.Content[i], lines, lineOffsets, edits); err != nil {
			return err
		}
	}

	return nil
}

func locateScalarSpan(node *yaml.Node, lines []string, lineOffsets []int) (int, int, error) {
	if node.Line <= 0 || node.Line > len(lines) {
		return 0, 0, fmt.Errorf("invalid node line: %d", node.Line)
	}

	lineIdx := node.Line - 1
	line := lines[lineIdx]
	startInLine := byteIndexAtColumn(line, node.Column)
	start := lineOffsets[lineIdx] + startInLine

	switch node.Style {
	case yaml.LiteralStyle, yaml.FoldedStyle:
		end := locateBlockScalarEnd(node, lines, lineOffsets)
		return start, end, nil
	default:
		endInLine := locateInlineScalarEnd(node, line, startInLine)
		end := lineOffsets[lineIdx] + endInLine
		return start, end, nil
	}
}

func locateBlockScalarEnd(node *yaml.Node, lines []string, lineOffsets []int) int {
	headerLine := node.Line - 1
	headerIndent := leadingSpaces(lines[headerLine])
	endLine := len(lines)

	for i := headerLine + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if leadingSpaces(line) <= headerIndent {
			endLine = i
			break
		}
	}

	if endLine >= len(lines) {
		return len(strings.Join(lines, "\n"))
	}
	return lineOffsets[endLine]
}

func locateInlineScalarEnd(node *yaml.Node, line string, start int) int {
	if start >= len(line) {
		return len(line)
	}

	switch node.Style {
	case yaml.DoubleQuotedStyle:
		return findDoubleQuotedEnd(line, start)
	case yaml.SingleQuotedStyle:
		return findSingleQuotedEnd(line, start)
	default:
		return findPlainScalarEnd(line, start)
	}
}

func findDoubleQuotedEnd(line string, start int) int {
	for i := start + 1; i < len(line); i++ {
		if line[i] == '"' && line[i-1] != '\\' {
			return i + 1
		}
	}
	return len(line)
}

func findSingleQuotedEnd(line string, start int) int {
	for i := start + 1; i < len(line); i++ {
		if line[i] != '\'' {
			continue
		}
		if i+1 < len(line) && line[i+1] == '\'' {
			i++
			continue
		}
		return i + 1
	}
	return len(line)
}

func findPlainScalarEnd(line string, start int) int {
	commentPos := -1
	for i := start; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			commentPos = i
			break
		}
	}
	if commentPos == -1 {
		return len(strings.TrimRight(line, " \t"))
	}
	j := commentPos - 1
	for j >= start && (line[j] == ' ' || line[j] == '\t') {
		j--
	}
	return j + 1
}

func renderScalarReplacement(originalNode, processedNode *yaml.Node, lines []string) string {
	originalStyle := originalNode.Style
	value := processedNode.Value

	if originalStyle == yaml.LiteralStyle || originalStyle == yaml.FoldedStyle {
		indicator := defaultBlockScalarIndicator(originalStyle)
		indicator = extractBlockScalarIndicator(originalNode, lines, indicator)

		headerLine := lines[originalNode.Line-1]
		contentIndent := strings.Repeat(" ", leadingSpaces(headerLine)+2)
		lines := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			return indicator
		}
		for i := range lines {
			lines[i] = contentIndent + lines[i]
		}
		return indicator + "\n" + strings.Join(lines, "\n") + "\n"
	}

	inlineStyle := processedNode.Style
	if originalStyle == yaml.DoubleQuotedStyle || originalStyle == yaml.SingleQuotedStyle {
		inlineStyle = originalStyle
	}
	return renderInlineScalar(value, inlineStyle)
}

func defaultBlockScalarIndicator(style yaml.Style) string {
	if style == yaml.FoldedStyle {
		return ">"
	}
	return "|"
}

func extractBlockScalarIndicator(node *yaml.Node, lines []string, fallback string) string {
	if node == nil || node.Line <= 0 || node.Line > len(lines) {
		return fallback
	}

	headerLine := lines[node.Line-1]
	start := byteIndexAtColumn(headerLine, node.Column)
	if start < 0 || start >= len(headerLine) {
		return fallback
	}

	if headerLine[start] != '|' && headerLine[start] != '>' {
		return fallback
	}

	end := start + 1
	for end < len(headerLine) {
		ch := headerLine[end]
		if (ch >= '0' && ch <= '9') || ch == '+' || ch == '-' {
			end++
			continue
		}
		break
	}

	indicator := headerLine[start:end]
	if indicator == "" {
		return fallback
	}
	return indicator
}

func renderInlineScalar(value string, style yaml.Style) string {
	switch style {
	case yaml.DoubleQuotedStyle:
		return `"` + escapeDoubleQuoted(value) + `"`
	case yaml.SingleQuotedStyle:
		return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
	default:
		if needsQuoting(value) {
			return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
		}
		return value
	}
}

func escapeDoubleQuoted(value string) string {
	replacer := strings.NewReplacer(
		`\\`, `\\\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\t", `\t`,
		"\r", `\r`,
	)
	return replacer.Replace(value)
}

func needsQuoting(value string) bool {
	if value == "" {
		return true
	}
	if strings.ContainsAny(value, "\n\r\t") {
		return true
	}
	if strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
		return true
	}
	if strings.Contains(value, ": ") || strings.Contains(value, " #") {
		return true
	}
	if strings.HasPrefix(value, "- ") || strings.HasPrefix(value, "? ") || strings.HasPrefix(value, "!") {
		return true
	}
	return false
}

func byteIndexAtColumn(line string, column int) int {
	if column <= 1 {
		return 0
	}
	idx := 0
	for currentCol := 1; currentCol < column && idx < len(line); currentCol++ {
		_, size := utf8.DecodeRuneInString(line[idx:])
		if size <= 0 {
			break
		}
		idx += size
	}
	return idx
}

func leadingSpaces(s string) int {
	count := 0
	for _, r := range s {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

// Structure to hold information about folded style sections
type FoldedStyleSection struct {
	Key         string
	IndentLevel int
	Content     string
}

// protectFoldedStyleSections scans the YAML file for folded style sections and replaces them with placeholders.
// This allows preserving the folded style (> or >-) formatting which isn't directly supported by the YAML parser
// during encryption/decryption operations.
//
// It works by:
// 1. Identifying lines that start a folded section (having the '>' or '>-' indicator)
// 2. Replacing those sections with placeholders temporarily
// 3. Returning both the modified content and information about the original sections
//
// Parameters:
//   - content: The original YAML file content
//   - debug: Whether to output debug information
//
// Returns:
//   - []FoldedStyleSection: Information about the found folded style sections
//   - []byte: Modified YAML content with placeholders instead of folded sections
func protectFoldedStyleSections(content []byte, debug bool) ([]FoldedStyleSection, []byte) {
	lines := strings.Split(string(content), "\n")
	var foldedSections []FoldedStyleSection
	var newLines []string

	inFoldedSection := false
	var currentSection FoldedStyleSection
	var currentIndent int

	lineRegex := regexp.MustCompile(`^(\s*)([^:]+):\s*>-?\s*$`)

	for i, line := range lines {
		if !inFoldedSection {
			// Check if line starts a folded section (has > or >-)
			matches := lineRegex.FindStringSubmatch(line)
			if len(matches) > 0 {
				indent := len(matches[1])
				key := matches[2]
				inFoldedSection = true
				currentSection = FoldedStyleSection{
					Key:         key,
					IndentLevel: indent,
					Content:     line + "\n", // Start with the key line
				}
				currentIndent = indent + YAMLIndentSpaces // Expected indent for content is key indent + standard YAML indentation

				// Add placeholder instead of the folded style line
				newLines = append(newLines, fmt.Sprintf("%s%s: \"FOLDED_STYLE_PLACEHOLDER_%d\"", matches[1], key, len(foldedSections)))
				debugLog(debug, "Found folded style section for key: %s at line %d", key, i+1)
				continue
			}
		} else {
			// We're in a folded section, check if this line continues the section
			if len(line) == 0 || strings.HasPrefix(line, strings.Repeat(" ", currentIndent)) {
				// This line is part of the folded section
				currentSection.Content += line + "\n"
				continue
			} else {
				// This line is not part of the folded section anymore
				inFoldedSection = false
				foldedSections = append(foldedSections, currentSection)
				debugLog(debug, "Completed folded style section: %s", currentSection.Key)
			}
		}

		// Add regular lines to the output
		newLines = append(newLines, line)
	}

	// If we're still in a folded section at the end of the file
	if inFoldedSection {
		foldedSections = append(foldedSections, currentSection)
		debugLog(debug, "Completed folded style section at end of file: %s", currentSection.Key)
	}

	return foldedSections, []byte(strings.Join(newLines, "\n"))
}

// restoreFoldedStyleSections restores the original folded style sections in the processed YAML content.
// It replaces the placeholders created by protectFoldedStyleSections with the original folded content.
//
// Parameters:
//   - processedContent: The processed YAML content with placeholders
//   - foldedSections: The original folded style sections to restore
//   - debug: Whether to output debug information
//
// Returns:
//   - []byte: The final YAML content with restored folded style sections
func restoreFoldedStyleSections(processedContent []byte, foldedSections []FoldedStyleSection, debug bool) []byte {
	content := string(processedContent)

	// Replace each placeholder with its original folded style content
	for i, section := range foldedSections {
		placeholder := fmt.Sprintf("\"FOLDED_STYLE_PLACEHOLDER_%d\"", i)
		debugLog(debug, "Restoring folded style section: %s", section.Key)

		// Remove the first line (the key line) and create the folded section again
		contentLines := strings.Split(section.Content, "\n")
		if len(contentLines) > 1 {
			// Remove the first line (the key line) and create the folded section again
			sectionContent := strings.Join(contentLines[1:], "\n")
			// Create the key line with folded style
			keyLine := fmt.Sprintf("%s%s: >-", strings.Repeat(" ", section.IndentLevel), section.Key)

			// Put it all together with proper indentation
			replacement := keyLine + "\n" + sectionContent
			content = strings.Replace(content, placeholder, "", 1) // Remove the placeholder

			// Find where to insert the folded content
			pattern := fmt.Sprintf("(%s%s:)[^\n]*\n", strings.Repeat(" ", section.IndentLevel), regexp.QuoteMeta(section.Key))
			re := regexp.MustCompile(pattern)
			content = re.ReplaceAllString(content, replacement)
		}
	}

	return []byte(content)
}

// ShowDiff shows the difference between original and processed YAML
func ShowDiff(filePath, key, operation string, debug bool, configPath string) error {
	debugLog(debug, "[ShowDiff] Starting with config path: '%s', type: %T", configPath, configPath)

	// Safe logging of key - showing only last 4 characters
	safeKeyLog := "****"
	if len(key) > minKeyLengthToShow {
		safeKeyLog = "****" + key[len(key)-4:]
	}
	debugLog(debug, "[ShowDiff] Using key ending with: %s", safeKeyLog)

	// Convert relative configPath to absolute if needed
	if configPath != "" && !filepath.IsAbs(configPath) {
		absConfigPath, err := filepath.Abs(configPath)
		if err == nil {
			configPath = absConfigPath
			debugLog(debug, "Using absolute config path: %s", configPath)
		} else {
			debugLog(debug, "Failed to get absolute path for %s: %v", configPath, err)
		}
	}

	debugLog(debug, "[ShowDiff] Using config path: %s", configPath)

	content, err := os.ReadFile(filePath) // #nosec G304 -- file path is intentionally provided by the caller
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Parse YAML content
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		return fmt.Errorf("error parsing YAML: %w", err)
	}

	_, config, err := loadRules(configPath, debug)
	if err != nil {
		return fmt.Errorf("error loading rules: %w", err)
	}

	// Log unsecureDiff value for debugging purposes
	debugLog(debug, "Loaded unsecureDiff value from config: %v", config.Encryption.UnsecureDiff)

	showDiff(&node, key, operation, config.Encryption.UnsecureDiff, debug, configPath)
	return nil
}

// readYAMLWithBuffer reads YAML file with buffering
func readYAMLWithBuffer(filename string) (_ *yaml.Node, err error) {
	file, err := os.Open(filename) // #nosec G304 -- filename is intentionally provided by internal call sites
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	// Create buffered reader
	reader := bufio.NewReader(file)
	decoder := yaml.NewDecoder(reader)
	var data yaml.Node
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

// writeYAMLWithBuffer writes YAML file with buffering
func writeYAMLWithBuffer(filename string, data *yaml.Node) error {
	file, err := os.Create(filename) // #nosec G304 -- filename is intentionally provided by internal call sites
	if err != nil {
		return err
	}

	// Create buffered writer
	writer := bufio.NewWriter(file)

	encoder := yaml.NewEncoder(writer)
	encoder.SetIndent(DefaultIndent)
	if err := encoder.Encode(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// clearNodeData recursively clears sensitive data from the node
func clearNodeData(node *yaml.Node) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if strings.HasPrefix(node.Value, AES) {
			node.Value = ""
		}
	case yaml.SequenceNode, yaml.MappingNode:
		for _, child := range node.Content {
			clearNodeData(child)
		}
	}
}

// maskNodeValues recursively masks encrypted values in YAML nodes
func maskNodeValues(node *yaml.Node, debug bool) *yaml.Node {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if strings.HasPrefix(node.Value, AES) {
			node.Value = maskEncryptedValue(node.Value, debug)
		}
		return node
	case yaml.SequenceNode:
		for _, child := range node.Content {
			maskNodeValues(child, debug)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 < len(node.Content) {
				maskNodeValues(node.Content[i+1], debug)
			}
		}
	}
	return node
}

// loadRules loads encryption rules from a config file
func loadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	// Convert relative configFile to absolute if needed
	configFile = resolveConfigPath(configFile, debug)

	debugLog(debug, "[loadRules] Config file is: '%s'", configFile)

	// Read and parse config file
	config, err := readAndParseConfig(configFile, debug)
	if err != nil {
		return nil, nil, err
	}

	// Initialize rules slice with main config rules
	allRules := config.Encryption.Rules

	// Process included rules
	includedRules, err := processIncludedRules(config, configFile, debug)
	if err != nil {
		return nil, nil, err
	}

	// Combine main rules with included rules
	allRules = append(allRules, includedRules...)

	// Check if we found any rules at all
	if len(allRules) == 0 {
		debugLog(debug, "Warning: no rules found in main config or included files")
	} else {
		debugLog(debug, "Loaded a total of %d rules", len(allRules))
	}

	// Replace the original rules with the combined set
	config.Encryption.Rules = allRules

	// Validate rules
	if err := validateRules(config, debug); err != nil {
		return nil, nil, err
	}

	// Log unsecure_diff setting
	logUnsecureDiffSetting(config, debug)

	// Copy UnsecureDiff value from encryption settings to main configuration
	config.UnsecureDiff = config.Encryption.UnsecureDiff

	debugLog(debug, "Loaded %d rules in total", len(config.Encryption.Rules))
	return config.Encryption.Rules, config, nil
}

// resolveConfigPath converts relative configFile to absolute if needed
func resolveConfigPath(configFile string, debug bool) string {
	if configFile != "" && !filepath.IsAbs(configFile) {
		absConfigFile, err := filepath.Abs(configFile)
		if err == nil {
			configFile = absConfigFile
			debugLog(debug, "Using absolute config path in LoadRules: %s", configFile)
		} else {
			debugLog(debug, "Failed to get absolute path for %s: %v", configFile, err)
		}
	}
	return configFile
}

// readAndParseConfig reads and parses a YAML config file
func readAndParseConfig(configFile string, debug bool) (*Config, error) {
	// Read config file
	content, err := os.ReadFile(configFile) // #nosec G304 -- config file path is intentionally provided by the caller
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse config
	var config Config
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return &config, nil
}

// processIncludedRules loads rules from included rule files
func processIncludedRules(config *Config, configFile string, debug bool) ([]Rule, error) {
	// Get the directory of the main config file to resolve relative paths
	configDir := filepath.Dir(configFile)

	// Log main config rules if found
	if len(config.Encryption.Rules) > 0 {
		debugLog(debug, "Found %d rules in main config file", len(config.Encryption.Rules))
	} else {
		debugLog(debug, "No rules found in main config, checking include_rules...")
	}

	return loadIncludedRules(config.Encryption.IncludeRules, configDir, debug, "included rules")
}

// validateRules validates the loaded rules
func validateRules(config *Config, debug bool) error {
	// Skip validation if disabled or no rules
	if !isRuleValidationEnabled(config) || len(config.Encryption.Rules) == 0 {
		return nil
	}

	// Basic validation - check for required fields
	for _, rule := range config.Encryption.Rules {
		if rule.Block == "" {
			return fmt.Errorf("rule '%s' is missing block", rule.Name)
		}
		if rule.Pattern == "" {
			return fmt.Errorf("rule '%s' is missing pattern", rule.Name)
		}
	}

	// Check for duplicate rules
	if duplicates := checkDuplicateRules(config.Encryption.Rules, debug); len(duplicates) > 0 {
		// If in debug mode, log all duplicates but still return an error for the first one
		if debug {
			for _, dup := range duplicates {
				debugLog(debug, "[WARN] Duplicate rule found: %s", dup)
			}
		}
		// Return first duplicate as error
		return fmt.Errorf("rule conflict detected: %s", duplicates[0])
	}

	return nil
}

func isRuleValidationEnabled(config *Config) bool {
	if config == nil || config.Encryption.ValidateRules == nil {
		return true
	}
	return *config.Encryption.ValidateRules
}

// logUnsecureDiffSetting logs a warning if unsecure_diff is enabled
func logUnsecureDiffSetting(config *Config, debug bool) {
	if config.Encryption.UnsecureDiff {
		debugLog(debug, "WARNING: unsecure_diff is set to TRUE. Some sensitive data will be visible in diff mode, "+
			"but password and encryption keys will still be masked.")
	} else {
		debugLog(debug, "unsecure_diff is set to FALSE. All sensitive data will be masked in diff mode.")
	}
}

// Constants for working with rules
const (
	// RangeRegexMatchCount represents the expected number of groups in the range expression [0-9]
	RangeRegexMatchCount = 3
)

var includeRangeRegex = regexp.MustCompile(`\[(\d+)-(\d+)\]`)

func isExplicitIncludeRuleFile(pattern string) bool {
	return !strings.ContainsAny(pattern, "*?") && !includeRangeRegex.MatchString(pattern)
}

func resolveIncludePattern(pattern, baseDir string) string {
	if filepath.IsAbs(pattern) {
		return pattern
	}
	return filepath.Clean(filepath.Join(baseDir, pattern))
}

func loadIncludedRules(rulePatterns []string, configDir string, debug bool, label string) ([]Rule, error) {
	var includedRules []Rule

	for _, rulePattern := range rulePatterns {
		if isExplicitIncludeRuleFile(rulePattern) {
			resolvedPattern := resolveIncludePattern(rulePattern, configDir)
			rules, err := loadRulesFromFile(resolvedPattern, debug)
			if err != nil {
				return nil, fmt.Errorf("failed to load %s from file '%s': %w", label, rulePattern, err)
			}
			includedRules = append(includedRules, rules...)
			continue
		}

		rules, err := loadRulesFromPattern(rulePattern, configDir, debug)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s from pattern '%s': %w", label, rulePattern, err)
		}
		includedRules = append(includedRules, rules...)
	}

	return includedRules, nil
}

// loadRulesFromPattern loads rules from files matching a pattern
// Supports patterns like "rules[1-3].yml" or "*.yml"
func loadRulesFromPattern(pattern string, baseDir string, debug bool) ([]Rule, error) {
	var allRules []Rule

	pattern = resolveIncludePattern(pattern, baseDir)

	debugLog(debug, "Resolving pattern '%s' (baseDir: '%s')", pattern, baseDir)

	// Check if the pattern contains range syntax like [1-3]
	matches := includeRangeRegex.FindStringSubmatch(pattern)

	if len(matches) == RangeRegexMatchCount {
		// Extract range bounds
		start, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid range start in pattern '%s': %w", pattern, err)
		}

		end, err := strconv.Atoi(matches[2])
		if err != nil {
			return nil, fmt.Errorf("invalid range end in pattern '%s': %w", pattern, err)
		}

		debugLog(debug, "Processing range pattern from %d to %d", start, end)

		// For each number in the range, construct the specific filename and check if it exists
		for i := start; i <= end; i++ {
			specificFile := strings.Replace(pattern, matches[0], strconv.Itoa(i), 1)
			debugLog(debug, "Checking specific file for range pattern: %s", specificFile)

			// Verify file exists and is valid
			rules, err := loadRulesFromFile(specificFile, debug)
			if err != nil {
				// Log the error but continue with other files
				debugLog(debug, "Error loading rules from '%s': %v", specificFile, err)
				continue
			}

			allRules = append(allRules, rules...)
		}
	} else {
		// Use filepath.Glob for wildcard patterns
		debugLog(debug, "Using glob pattern: %s", pattern)
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("error processing glob pattern '%s': %w", pattern, err)
		}

		if len(matches) == 0 {
			debugLog(debug, "No files found matching pattern '%s'", pattern)
		} else {
			debugLog(debug, "Found %d files matching pattern '%s'", len(matches), pattern)
		}

		for _, filePath := range matches {
			// Skip if not .yml or .yaml
			if !hasYamlExtension(filePath) {
				debugLog(debug, "Skipping non-YAML file: %s", filePath)
				continue
			}

			rules, err := loadRulesFromFile(filePath, debug)
			if err != nil {
				// Log the error but continue with other files
				debugLog(debug, "Error loading rules from '%s': %v", filePath, err)
				continue
			}

			allRules = append(allRules, rules...)
		}
	}

	return allRules, nil
}

// loadRulesFromFile loads rules from a single file
func loadRulesFromFile(filePath string, debug bool) ([]Rule, error) {
	debugLog(debug, "Loading rules from file: %s", filePath)

	// Verify the file has a YAML extension
	if !hasYamlExtension(filePath) {
		return nil, fmt.Errorf("file '%s' is not a YAML file", filePath)
	}

	// Read and parse the file
	content, err := os.ReadFile(filePath) // #nosec G304 -- include file path comes from explicit include patterns
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Try to parse as a file with encryption.rules structure first
	var configWithEncryption struct {
		Encryption struct {
			Rules []Rule `yaml:"rules"`
		} `yaml:"encryption"`
	}

	if err := yaml.Unmarshal(content, &configWithEncryption); err != nil {
		debugLog(debug, "Error parsing file as encryption.rules structure: %v", err)
	}

	// If we found rules in the encryption.rules structure, use those
	if len(configWithEncryption.Encryption.Rules) > 0 {
		debugLog(debug, "Loaded %d rules from encryption.rules in file '%s'", len(configWithEncryption.Encryption.Rules), filePath)
		return configWithEncryption.Encryption.Rules, nil
	}

	// Try to parse with rules at the top level
	var configWithRules struct {
		Rules []Rule `yaml:"rules"`
	}

	if err := yaml.Unmarshal(content, &configWithRules); err != nil {
		return nil, fmt.Errorf("error parsing YAML in file '%s': %w", filePath, err)
	}

	debugLog(debug, "Loaded %d rules from top-level rules in file '%s'", len(configWithRules.Rules), filePath)
	return configWithRules.Rules, nil
}

// hasYamlExtension checks if a file has .yml or .yaml extension
func hasYamlExtension(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".yml" || ext == ".yaml"
}

// checkDuplicateRules checks for duplicate rules based on name, and on block+pattern+action combination
func checkDuplicateRules(rules []Rule, debug bool) []string {
	var duplicates []string
	ruleMap := make(map[string]map[string]map[string]int) // block -> pattern -> action -> line number
	nameMap := make(map[string]int)                       // rule name -> line number

	for i, rule := range rules {
		// Check for duplicate rule names
		if previousLine, exists := nameMap[rule.Name]; exists {
			// Calculate actual line numbers in YAML file
			duplicateLine := i*linesPerRule + firstRuleOffset
			originalLine := previousLine*linesPerRule + firstRuleOffset
			msg := fmt.Sprintf("Duplicate rule name found: line %d: rule '%s' duplicates rule name at line %d",
				duplicateLine, rule.Name, originalLine)
			duplicates = append(duplicates, msg)
		} else {
			nameMap[rule.Name] = i
		}

		// Check for duplicate rule configurations (block + pattern + action)
		if _, exists := ruleMap[rule.Block]; !exists {
			ruleMap[rule.Block] = make(map[string]map[string]int)
		}
		if _, exists := ruleMap[rule.Block][rule.Pattern]; !exists {
			ruleMap[rule.Block][rule.Pattern] = make(map[string]int)
		}
		if line, exists := ruleMap[rule.Block][rule.Pattern][rule.Action]; exists {
			// Calculate actual line numbers in YAML file
			duplicateLine := i*linesPerRule + firstRuleOffset
			originalLine := line*linesPerRule + firstRuleOffset
			msg := fmt.Sprintf("Duplicate rule configuration found: line %d: rule '%s' (block: '%s', pattern: '%s', action: '%s') duplicates rule at line %d",
				duplicateLine, rule.Name, rule.Block, rule.Pattern, rule.Action, originalLine)
			duplicates = append(duplicates, msg)
		} else {
			ruleMap[rule.Block][rule.Pattern][rule.Action] = i
		}
	}

	return duplicates
}

// processRules processes rules in order of priority
func processRules(path string, rules []Rule, debug bool) (string, bool) {
	debugLog(debug, "Processing rules for path: %s", path)

	// Backward-compatible mode: if no rules provided, process all scalar paths.
	if len(rules) == 0 {
		debugLog(debug, "No rules configured, processing path by default: %s", path)
		return "default-all", true
	}

	// Check rules with action=none first
	for _, rule := range rules {
		if rule.Action == ActionNone && matchesRule(path, rule, debug) {
			debugLog(debug, "Path %s matches 'none' action rule %s - skipping encryption", path, rule.Name)
			return "", false
		}
	}

	// Then check rules with other actions
	for _, rule := range rules {
		if rule.Action != ActionNone && matchesRule(path, rule, debug) {
			debugLog(debug, "Path %s matches rule %s for encryption", path, rule.Name)
			return rule.Name, true
		}
	}

	debugLog(debug, "No matching rules found for path: %s", path)
	return "", false
}

// ProcessNode processes a YAML node
func ProcessNode(node *yaml.Node, path, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	// Check for valid operation
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	debugLog(debug, "Processing node at path: %s", path)

	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) > 0 {
			return processNode(node.Content[0], path, key, operation, rules, processedPaths, debug)
		}
	case yaml.MappingNode:
		return processMappingNode(node, path, key, operation, rules, processedPaths, debug)
	case yaml.SequenceNode:
		return processSequenceNode(node, path, key, operation, rules, processedPaths, debug)
	case yaml.ScalarNode:
		return processScalarNode(node, path, key, operation, rules, processedPaths, debug)
	}

	return nil
}

// processNode processes a node with exclusions for paths matching 'none' action rules
func processNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		return processMappingNode(node, path, key, operation, rules, processedPaths, debug)
	case yaml.SequenceNode:
		return processSequenceNode(node, path, key, operation, rules, processedPaths, debug)
	case yaml.ScalarNode:
		return processScalarNode(node, path, key, operation, rules, processedPaths, debug)
	default:
		return nil
	}
}

// processMappingNode processes a mapping node with exclusions for paths matching 'none' action rules
func processMappingNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("invalid mapping node")
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		if keyNode.Kind != yaml.ScalarNode {
			continue
		}

		var newPath string
		if path == "" {
			newPath = keyNode.Value
		} else {
			newPath = path + "." + keyNode.Value
		}

		if err := processNode(valueNode, newPath, key, operation, rules, processedPaths, debug); err != nil {
			return err
		}
	}

	return nil
}

// processSequenceNode processes a sequence node with exclusions for paths matching 'none' action rules
func processSequenceNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		newPath := fmt.Sprintf("%s[%d]", path, i)
		if err := processNode(item, newPath, key, operation, rules, processedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

// processScalarNode processes a scalar node with exclusions for paths matching 'none' action rules
func processScalarNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	debugLog(debug, "Processing scalar node at path: %s", path)
	logNodeDetails(node, path, debug)

	// Check if the path matches any rule
	ruleName, shouldProcess := processRules(path, rules, debug)
	if !shouldProcess {
		debugLog(debug, "Path %s does not match any rule, skipping", path)
		return nil
	}

	// If we've reached this point, the path matches a rule and should be processed
	debugLog(debug, "Path %s matches rule %s, processing", path, ruleName)

	// Skip nodes with style yaml.FlowStyle or empty values
	if shouldSkipNode(node, debug) {
		return nil
	}

	// Skip alias nodes
	if node.Kind == yaml.AliasNode {
		debugLog(debug, "Skipping alias node")
		return nil
	}

	// Check if node has already been processed
	if _, exists := processedPaths[path]; exists {
		debugLog(debug, "Path %s has already been processed, skipping", path)
		return nil
	}

	// For literal and folded styles, use a special handler
	if isMultilineStyleNode(node) {
		return processMultilineStyleNode(node, path, key, operation, processedPaths, debug)
	}

	// Process node based on operation
	switch operation {
	case OperationEncrypt:
		return encryptScalarNode(node, path, key, processedPaths, debug)
	case OperationDecrypt:
		return decryptScalarNode(node, path, key, processedPaths, debug)
	}

	return nil
}

// logNodeDetails logs node details
func logNodeDetails(node *yaml.Node, path string, debug bool) {
	debugLog(debug, "Processing node at path %s with style %v", path, node.Style)
	debugLog(debug, "Node value length: %d", len(node.Value))
	if len(node.Value) > previewNodeChars {
		debugLog(debug, "Node value first %d chars: '%s'", previewNodeChars, node.Value[:previewNodeChars])
	} else {
		debugLog(debug, "Node value: '%s'", node.Value)
	}
}

// shouldSkipNode checks if a node should be skipped
func shouldSkipNode(node *yaml.Node, debug bool) bool {
	if node.Style == yaml.FlowStyle || node.Value == "" {
		debugLog(debug, "Skipping node with flow style or empty value")
		return true
	}
	return false
}

// isMultilineStyleNode checks if a node is multiline
func isMultilineStyleNode(node *yaml.Node) bool {
	return node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle
}

// processMultilineStyleNode processes a multiline node
func processMultilineStyleNode(node *yaml.Node, path string, key, operation string, processedPaths map[string]bool, debug bool) error {
	debugLog(debug, "Using multiline processor for %s style node at path %s", GetStyleName(node.Style), path)
	processed, err := ProcessMultilineNode(node, path, key, operation, debug)
	if err != nil {
		return err
	}
	if processed {
		debugLog(debug, "Multiline node at path %s was processed successfully", path)
		// Mark path as processed
		processedPaths[path] = true
		return nil
	}
	return nil
}

// encryptScalarNode encrypts a scalar node
func encryptScalarNode(node *yaml.Node, path string, key string, processedPaths map[string]bool, debug bool) error {
	// Skip already encrypted values
	if strings.HasPrefix(node.Value, AES) {
		debugLog(debug, "Value at path %s is already encrypted", path)
		return nil
	}

	// Save the node's style for restoration after encryption
	initialStyle := node.Style

	// Encrypt the value
	debugLog(debug, "Encrypting value at path %s", path)
	encryptedValue, err := encryption.Encrypt(key, node.Value)
	if err != nil {
		return fmt.Errorf("error encrypting value at path %s: %v", path, err)
	}

	// Add style suffix based on the node's original style
	styleSuffix := getStyleSuffix(initialStyle)
	if styleSuffix != "|plain" {
		encryptedValue += styleSuffix
		debugLog(debug, "Added style suffix %s to encrypted value", styleSuffix)
	}

	// Set the encrypted value and mark as plain style
	node.Value = AES + encryptedValue
	debugLog(debug, "Encrypted node with style: %d", initialStyle)
	node.Style = 0 // Always set plain style for encrypted values

	// Mark path as processed
	processedPaths[path] = true
	return nil
}

// decryptScalarNode decrypts a scalar node
func decryptScalarNode(node *yaml.Node, path string, key string, processedPaths map[string]bool, debug bool) error {
	// Skip non-encrypted values
	if !strings.HasPrefix(node.Value, AES) {
		debugLog(debug, "Value at path %s is not encrypted", path)
		return nil
	}

	// Extract the encrypted value (skipping the AES marker)
	encrypted := strings.TrimPrefix(node.Value, AES)

	debugLog(debug, "DECRYPT TRACE - Path: %s, AES prefix removed, value length: %d", path, len(encrypted))
	if len(encrypted) > previewEncryptedChars {
		debugLog(debug, "DECRYPT TRACE - First %d chars: '%s'", previewEncryptedChars, encrypted[:previewEncryptedChars])
	} else {
		debugLog(debug, "DECRYPT TRACE - Full value: '%s'", encrypted)
	}

	// Decrypt the value
	decryptedValue, err := decryptNodeValue(encrypted, key, debug)
	if err != nil {
		return fmt.Errorf("error decrypting value at path %s: %v", path, err)
	}

	// Determine style from suffix
	styleInfo := yaml.Style(0) // Default plain style

	// Extract style suffix if present
	for _, styleName := range []string{StyleLiteral, StyleFolded, StyleDoubleQuoted, StyleSingleQuoted, StylePlain} {
		suffix := "|" + styleName
		if strings.HasSuffix(decryptedValue, suffix) {
			decryptedValue = decryptedValue[:len(decryptedValue)-len(suffix)]

			// Convert style suffix to yaml.Style
			switch styleName {
			case StyleLiteral:
				styleInfo = yaml.LiteralStyle
			case StyleFolded:
				styleInfo = yaml.FoldedStyle
			case StyleDoubleQuoted:
				styleInfo = yaml.DoubleQuotedStyle
			case StyleSingleQuoted:
				styleInfo = yaml.SingleQuotedStyle
			}

			debugLog(debug, "Found style suffix in decrypted value: %s, setting style to: %d", styleName, styleInfo)
			break
		}
	}

	// Set the decrypted value and apply style
	node.Value = decryptedValue
	applyNodeStyle(node, styleInfo, debug)

	// Mark path as processed
	processedPaths[path] = true
	return nil
}

// EvaluateCondition evaluates a condition with caching
func EvaluateCondition(condition string, value interface{}) bool {
	if condition == "" {
		return true
	}

	// Check if condition is a wildcard pattern
	if strings.Contains(condition, "*") {
		re, err := getCompiledRegex(wildcardToRegex(condition))
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", value))
	}

	// Direct comparison for non-wildcard conditions
	return fmt.Sprintf("%v", value) == condition
}

// deepCopyNode creates a deep copy of a YAML node
func deepCopyNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}

	newNode := &yaml.Node{
		Kind:        node.Kind,
		Style:       node.Style,
		Tag:         node.Tag,
		Value:       node.Value,
		Anchor:      node.Anchor,
		Alias:       deepCopyNode(node.Alias),
		Content:     make([]*yaml.Node, len(node.Content)),
		HeadComment: node.HeadComment,
		LineComment: node.LineComment,
		FootComment: node.FootComment,
		Line:        node.Line,
		Column:      node.Column,
	}

	for i, child := range node.Content {
		newNode.Content[i] = deepCopyNode(child)
	}

	return newNode
}

// showDiff displays differences between original and encrypted values
func showDiff(data *yaml.Node, key, operation string, unsecureDiff bool, debug bool, configPath string) {
	if data == nil || len(data.Content) == 0 {
		debugLog(debug, "showDiff: data is nil or empty")
		return
	}

	debugLog(debug, "[showDiff] Config path is: '%s', type: %T", configPath, configPath)

	// Setting global variable for masking in logs
	unsecureDiffLog = unsecureDiff
	debugLog(debug, "Starting showDiff with operation: %s, unsecureDiff: %v", operation, unsecureDiff)

	if unsecureDiff {
		debugLog(debug, "WARNING: Running in unsecure diff mode. Sensitive data may be shown, but highly sensitive data will still be masked.")
	}

	debugLog(debug, "Initial data content length: %d", len(data.Content))

	// Create deep copies of data for comparison
	originalData := deepCopyNode(data)
	encryptedData := deepCopyNode(data)

	debugLog(debug, "Original data content length: %d", len(originalData.Content))
	debugLog(debug, "Encrypted data content length: %d", len(encryptedData.Content))

	// Load rules
	rules, _, err := loadRules(configPath, debug)
	if err != nil {
		debugLog(debug, "Error loading rules: %v", err)
		return
	}

	if len(rules) == 0 {
		debugLog(debug, "No rules defined, no encryption will be performed")
		return
	}

	// Process original data
	debugLog(debug, "Processing original data")
	processNodeForDiff(originalData.Content[0], key, operation, true, debug, configPath)

	// Process encrypted data
	debugLog(debug, "Processing encrypted data")

	// Create a map to track paths that should be excluded from processing
	excludedPaths := make(map[string]bool)

	// First, identify all paths that should be excluded based on action: none rules
	for _, rule := range rules {
		if rule.Action == ActionNone {
			debugLog(debug, "Marking paths for exclusion based on rule: %s", rule.Name)
			if err := markExcludedPaths(encryptedData.Content[0], rule, "", excludedPaths, debug); err != nil {
				debugLog(debug, "Error marking excluded paths: %v", err)
			}
		}
	}

	// Then process all rules, skipping excluded paths
	for _, rule := range rules {
		if rule.Action != ActionNone {
			debugLog(debug, "Processing rule: %s", rule.Name)
			if err := processYAMLWithExclusions(encryptedData.Content[0], key, operation, rule, "", make(map[string]bool), excludedPaths, debug); err != nil {
				debugLog(debug, "Error processing YAML: %v", err)
			}
		}
	}

	// Output differences
	debugLog(debug, "Printing differences")
	printDiff(originalData.Content[0], encryptedData.Content[0], debug, unsecureDiff, "")
	debugLog(debug, "Finished showDiff")
}

// processScalarNodeForDiff processes a scalar node for displaying differences
func processScalarNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool, configPath string) {
	// Create secure buffers for sensitive data
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	if keyBuf == nil {
		log.Printf("Failed to create secure buffer for key")
		return
	}
	defer keyBuf.Destroy()

	nodeValueBuf := memguard.NewBufferFromBytes([]byte(node.Value))
	if nodeValueBuf == nil {
		log.Printf("Failed to create secure buffer for node value")
		return
	}
	defer nodeValueBuf.Destroy()

	// Check for sensitive data
	isSuperSensitive := strings.Contains(strings.ToLower(string(nodeValueBuf.Bytes())), "yed_encrypt_password") ||
		strings.Contains(strings.ToLower(string(nodeValueBuf.Bytes())), "password=")

	// Mask the value for debug output
	displayValue := string(nodeValueBuf.Bytes())
	if isSensitive := isSensitiveValue(displayValue); isSensitive || isSuperSensitive {
		displayValue = MaskedValue
	}

	debugLog(debug, "processNodeForDiff: Processing scalar node with value: '%s'", displayValue)

	if !isOriginal {
		// For encrypted data, apply the operation
		switch {
		case operation == OperationEncrypt && !strings.HasPrefix(string(nodeValueBuf.Bytes()), AES):
			debugLog(debug, "processNodeForDiff: Encrypting value")

			// Hide debug key
			debugKeyValue := string(keyBuf.Bytes())
			if len(debugKeyValue) > minKeyLength {
				debugKeyValue = "****" + debugKeyValue[len(debugKeyValue)-4:]
			}

			encryptedValue, err := encryption.Encrypt(string(keyBuf.Bytes()), string(nodeValueBuf.Bytes()))
			if err == nil {
				node.Value = AES + encryptedValue
				debugLog(debug, "processNodeForDiff: Value encrypted successfully with key ending in: %s", debugKeyValue)
			} else {
				debugLog(debug, "processNodeForDiff: Encryption error: %v", err)
			}
		case operation == OperationDecrypt && strings.HasPrefix(string(nodeValueBuf.Bytes()), AES):
			debugLog(debug, "processNodeForDiff: Decrypting value")

			// Hide debug key
			debugKeyValue := string(keyBuf.Bytes())
			if len(debugKeyValue) > minKeyLength {
				debugKeyValue = "****" + debugKeyValue[len(debugKeyValue)-4:]
			}

			decryptedBuffer, err := encryption.DecryptToString(strings.TrimPrefix(string(nodeValueBuf.Bytes()), AES), string(keyBuf.Bytes()))
			if err == nil {
				node.Value = decryptedBuffer
				debugLog(debug, "processNodeForDiff: Value decrypted successfully with key ending in: %s", debugKeyValue)
			} else {
				debugLog(debug, "processNodeForDiff: Decryption error: %v", err)
			}
		}
	}
}

// isSensitiveValue determines if a value is sensitive
// We consider sensitive all strings that are not AES256 labels and longer than 6 characters
// If unsecureDiff == true, then we don't consider values as sensitive, except for passwords
var unsecureDiffLog bool = false // Global variable to store unsecureDiff value

var (
	diffOutputMu sync.RWMutex
	diffOutput   io.Writer
)

// SetDiffOutput configures where diff output is written.
// Passing nil resets output destination to os.Stdout.
func SetDiffOutput(w io.Writer) {
	diffOutputMu.Lock()
	defer diffOutputMu.Unlock()
	diffOutput = w
}

func getDiffOutput() io.Writer {
	diffOutputMu.RLock()
	defer diffOutputMu.RUnlock()
	if diffOutput == nil {
		return os.Stdout
	}
	return diffOutput
}

func isSensitiveValue(value string) bool {
	// Always consider highly sensitive passwords and encryption keys
	if strings.Contains(strings.ToLower(value), "password") ||
		strings.Contains(value, "YED_ENCRYPTION_KEY") {
		return true
	}

	if unsecureDiffLog {
		return false // Don't mask anything else if unsecureDiffLog is true
	}

	return !strings.HasPrefix(value, AES) && len(value) > MinEncryptedLength
}

// processSequenceNodeForDiff processes a sequence node for displaying differences
func processSequenceNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool, configPath string) {
	debugLog(debug, "processNodeForDiff: Processing sequence node with %d items", len(node.Content))
	for i, child := range node.Content {
		debugLog(debug, "processNodeForDiff: Processing sequence item %d", i)
		processNodeForDiff(child, key, operation, isOriginal, debug, configPath)
	}
}

// processMappingNodeForDiff processes a mapping node for displaying differences
func processMappingNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool, configPath string) {
	debugLog(debug, "processNodeForDiff: Processing mapping node with %d pairs", len(node.Content)/KeyValuePairSize)
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 < len(node.Content) {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			debugLog(debug, "processNodeForDiff: Processing mapping pair with key: '%s'", keyNode.Value)
			processNodeForDiff(valueNode, key, operation, isOriginal, debug, configPath)
		}
	}
}

// processNodeForDiff processes a node for displaying differences
func processNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool, configPath string) {
	if node == nil {
		debugLog(debug, "processNodeForDiff: received nil node")
		return
	}

	debugLog(debug, "processNodeForDiff: Processing node of kind: %v", node.Kind)

	switch node.Kind {
	case yaml.ScalarNode:
		processScalarNodeForDiff(node, key, operation, isOriginal, debug, configPath)
	case yaml.SequenceNode:
		processSequenceNodeForDiff(node, key, operation, isOriginal, debug, configPath)
	case yaml.MappingNode:
		processMappingNodeForDiff(node, key, operation, isOriginal, debug, configPath)
	default:
		debugLog(debug, "processNodeForDiff: Unsupported node kind: %v", node.Kind)
	}
}

// printDiff prints the differences between two YAML nodes
func printDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string) {
	if original == nil || processed == nil {
		return
	}

	switch original.Kind {
	case yaml.MappingNode:
		printMappingDiff(original, processed, debug, unsecureDiff, path)
	case yaml.SequenceNode:
		printSequenceDiff(original, processed, debug, unsecureDiff, path)
	case yaml.ScalarNode:
		printScalarDiff(original, processed, debug, unsecureDiff, path)
	}
}

func printMappingDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string) {
	for i := 0; i < len(original.Content); i += 2 {
		if i+1 >= len(original.Content) || i+1 >= len(processed.Content) {
			continue
		}

		keyNode := original.Content[i]
		originalValue := original.Content[i+1]
		processedValue := processed.Content[i+1]

		var newPath string
		if path == "" {
			newPath = keyNode.Value
		} else {
			newPath = path + "." + keyNode.Value
		}

		printDiff(originalValue, processedValue, debug, unsecureDiff, newPath)
	}
}

func printSequenceDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string) {
	for i := 0; i < len(original.Content); i++ {
		if i >= len(processed.Content) {
			break
		}

		newPath := fmt.Sprintf("%s[%d]", path, i)
		printDiff(original.Content[i], processed.Content[i], debug, unsecureDiff, newPath)
	}
}

func printScalarDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string) {
	if original == nil || processed == nil {
		return
	}

	originalValue := original.Value
	processedValue := processed.Value

	// Don't show diffs for identical values
	if originalValue == processedValue {
		return
	}

	// Mask sensitive values in the output if not in unsecure mode
	if !unsecureDiff && strings.HasPrefix(processedValue, AES) {
		processedValue = maskEncryptedValue(processedValue, debug, path)
	}

	// Show the difference
	_, _ = fmt.Fprintf(getDiffOutput(), "%s:\n  [%d] - %s\n  [%d] + %s\n", path, original.Line, originalValue, processed.Line, processedValue)
}

// markExcludedPaths marks paths that should be excluded based on rules
func markExcludedPaths(node *yaml.Node, rule Rule, currentPath string, excludedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	// Check if block matches before checking the pattern
	if currentPath != "" {
		// For path "axel.fix.username" and block "axel.fix" we must mark this path as excluded
		if matchesRule(currentPath, rule, debug) {
			debugLog(debug, "Marking path for exclusion based on rule '%s': %s", rule.Name, currentPath)
			excludedPaths[currentPath] = true
		}
	}

	switch node.Kind {
	case yaml.MappingNode:
		return markExcludedPathsMapping(node, rule, currentPath, excludedPaths, debug)
	case yaml.SequenceNode:
		return markExcludedPathsSequence(node, rule, currentPath, excludedPaths, debug)
	}

	return nil
}

func markExcludedPathsMapping(node *yaml.Node, rule Rule, currentPath string, excludedPaths map[string]bool, debug bool) error {
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			continue
		}

		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		var newPath string
		if currentPath == "" {
			newPath = keyNode.Value
		} else {
			newPath = currentPath + "." + keyNode.Value
		}

		if err := markExcludedPaths(valueNode, rule, newPath, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

func markExcludedPathsSequence(node *yaml.Node, rule Rule, currentPath string, excludedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		newPath := fmt.Sprintf("%s[%d]", currentPath, i)
		if err := markExcludedPaths(item, rule, newPath, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

// processYAMLWithExclusions processes YAML content while respecting excluded paths
func processYAMLWithExclusions(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths, excludedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	// Check if this path should be excluded
	if excludedPaths[currentPath] {
		debugLog(debug, "Skipping excluded path: %s", currentPath)
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		return processMappingNodeWithRuleExclusions(node, key, operation, rule, currentPath, processedPaths, excludedPaths, debug)
	case yaml.SequenceNode:
		return processSequenceNodeWithRuleExclusions(node, key, operation, rule, currentPath, processedPaths, excludedPaths, debug)
	case yaml.ScalarNode:
		return processScalarNodeWithRuleExclusions(node, key, operation, rule, currentPath, processedPaths, excludedPaths, debug)
	default:
		return nil
	}
}

// processMappingNodeWithRuleExclusions processes a mapping node with exclusions
func processMappingNodeWithRuleExclusions(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths, excludedPaths map[string]bool, debug bool) error {
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			continue
		}

		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		var newPath string
		if currentPath == "" {
			newPath = keyNode.Value
		} else {
			newPath = currentPath + "." + keyNode.Value
		}

		if err := processYAMLWithExclusions(valueNode, key, operation, rule, newPath, processedPaths, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

// processSequenceNodeWithRuleExclusions processes a sequence node with exclusions
func processSequenceNodeWithRuleExclusions(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths, excludedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		newPath := fmt.Sprintf("%s[%d]", currentPath, i)
		if err := processYAMLWithExclusions(item, key, operation, rule, newPath, processedPaths, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

// processScalarNodeWithRuleExclusions processes a scalar node with exclusions
func processScalarNodeWithRuleExclusions(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths, excludedPaths map[string]bool, debug bool) error {
	if !excludedPaths[currentPath] && matchesRule(currentPath, rule, debug) {
		debugLog(debug, "Processing scalar node at path: %s", currentPath)

		// Process multiline nodes first
		processed, err := ProcessMultilineNode(node, currentPath, key, operation, debug)
		if err != nil {
			return fmt.Errorf("failed to process multiline node at path %s: %w", currentPath, err)
		}

		// If the node was processed as multiline, mark it and return
		if processed {
			processedPaths[currentPath] = true
			debugLog(debug, "Successfully processed multiline node at path %s", currentPath)
			return nil
		}

		// Standard processing for regular nodes
		processedPaths[currentPath] = true

		switch operation {
		case OperationEncrypt:
			return processEncryptionWithExclusions(node, key, currentPath, debug)
		case OperationDecrypt:
			return processDecryptionWithExclusions(node, key, currentPath, processedPaths, debug)
		}
	}
	return nil
}

// processEncryptionWithExclusions processes a scalar node for encryption with exclusions
func processEncryptionWithExclusions(node *yaml.Node, key, currentPath string, debug bool) error {
	if !strings.HasPrefix(node.Value, AES) {
		// Save style information
		styleSuffix := getStyleSuffix(node.Style)

		// Save the current value before encryption
		originalValue := node.Value

		encrypted, err := encryption.Encrypt(key, originalValue)
		if err != nil {
			return fmt.Errorf("failed to encrypt value at path %s: %w", currentPath, err)
		}

		// Add style suffix to the encrypted value
		node.Value = AES + encrypted + styleSuffix

		// Reset style to plain for encrypted values
		node.Style = 0
	}
	return nil
}

// getStyleSuffix returns the style suffix for a given style
func getStyleSuffix(style yaml.Style) string {
	switch style {
	case yaml.LiteralStyle:
		return "|" + StyleLiteral
	case yaml.FoldedStyle:
		return "|" + StyleFolded
	case yaml.DoubleQuotedStyle:
		return "|" + StyleDoubleQuoted
	case yaml.SingleQuotedStyle:
		return "|" + StyleSingleQuoted
	default:
		return "|" + StylePlain
	}
}

// processDecryptionWithExclusions processes a scalar node for decryption with exclusions
func processDecryptionWithExclusions(node *yaml.Node, key, currentPath string, processedPaths map[string]bool, debug bool) error {
	if strings.HasPrefix(node.Value, AES) {
		debugLog(debug, "Processing encrypted node with value: %s", maskEncryptedValue(node.Value, debug, currentPath))

		// Extract the encrypted value (skipping the AES marker) and handle style suffix
		encrypted := strings.TrimPrefix(node.Value, AES)

		// Decrypt the value
		decryptedValue, err := decryptNodeValue(encrypted, key, debug)
		if err != nil {
			return err
		}

		// Set the decrypted value and apply style
		node.Value = decryptedValue
		applyNodeStyle(node, 0, debug)

		// Mark path as processed
		if processedPaths != nil {
			processedPaths[currentPath] = true
		}
	}
	return nil
}

// decryptNodeValue decrypts a scalar node value
func decryptNodeValue(encrypted, key string, debug bool) (string, error) {
	debugLog(debug, "Starting decryptNodeValue with encrypted value of length %d", len(encrypted))
	if len(encrypted) > previewEncryptedChars {
		debugLog(debug, "First %d chars of encrypted value: '%s'", previewEncryptedChars, encrypted[:previewEncryptedChars])
	} else {
		debugLog(debug, "Full encrypted value: '%s'", encrypted)
	}

	// Clean up multiline data
	encrypted = cleanMultilineEncrypted(encrypted, debug)

	// Extract style suffix
	cleanedEncrypted, styleSuffix := extractStyleSuffix(encrypted, debug)
	encrypted = cleanedEncrypted

	debugLog(debug, "After style suffix extraction, encrypted value length: %d", len(encrypted))
	if len(encrypted) > previewEncryptedChars {
		debugLog(debug, "First %d chars: '%s'", previewEncryptedChars, encrypted[:previewEncryptedChars])
	} else {
		debugLog(debug, "Full encrypted value: '%s'", encrypted)
	}

	// Check for very short string that might not be encrypted
	if len(encrypted) < MinEncryptedLength {
		debugLog(debug, "WARNING: Encrypted value too short (%d bytes), might not be encrypted data: '%s'",
			len(encrypted), encrypted)
		// It might be unencrypted data - return as is
		if styleSuffix != "" {
			return encrypted + styleSuffix, nil
		}
		return encrypted, nil
	}

	// Encryption.Decrypt will handle style suffixes
	debugLog(debug, "Calling encryption.DecryptToString with cleaned value...")
	decryptedBuffer, err := encryption.DecryptToString(encrypted, key)
	if err != nil {
		debugLog(debug, "Error decrypting value: %v", err)
		// If error is related to Base64, try to fix the string
		if strings.Contains(err.Error(), "base64") {
			paddedEncrypted := fixBase64Padding(encrypted, debug)
			// Try again with fixed string
			debugLog(debug, "Retrying with padded Base64 string")
			if decryptedBuffer, err = encryption.DecryptToString(paddedEncrypted, key); err != nil {
				return "", err
			}
			return decryptedBuffer, nil
		}
		return "", err
	}

	// Return style suffix if it was present
	if styleSuffix != "" {
		decryptedBuffer += styleSuffix
	}

	// Log decryption result
	logDecryptionResult(decryptedBuffer, debug)

	return decryptedBuffer, nil
}

// GetStyleName returns the name of a style
func GetStyleName(style yaml.Style) string {
	switch style {
	case yaml.LiteralStyle:
		return "literal"
	case yaml.FoldedStyle:
		return "folded"
	case yaml.DoubleQuotedStyle:
		return "double_quoted"
	case yaml.SingleQuotedStyle:
		return "single_quoted"
	default:
		return "plain"
	}
}

// ProcessYAMLContent processes YAML content with the given rules (exported version)
func ProcessYAMLContent(content []byte, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) (*yaml.Node, error) {
	return processYAMLContent(content, key, operation, rules, processedPaths, debug)
}

// LoadRules loads encryption rules from a config file (exported version)
func LoadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	return loadRules(configFile, debug)
}

// ProcessDiff processes YAML content and shows differences
func ProcessDiff(content []byte, config Config) error {
	debugLog(config.Debug, "Processing diff")

	operation := config.Operation
	if operation == "" {
		operation = OperationEncrypt
	}
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return fmt.Errorf("invalid operation for diff: %s", operation)
	}

	// Parse original YAML
	var originalData yaml.Node
	if err := yaml.Unmarshal(content, &originalData); err != nil {
		return fmt.Errorf("error parsing original YAML: %w", err)
	}

	// Process content with the same pipeline used by file processing.
	processedPaths := make(map[string]bool)
	processedNode, err := processYAMLContent(content, config.Key, operation, config.Encryption.Rules, processedPaths, config.Debug)
	if err != nil {
		return fmt.Errorf("error processing YAML content: %w", err)
	}

	// Output differences
	debugLog(config.Debug, "Printing differences")
	printDiff(originalData.Content[0], processedNode.Content[0], config.Debug, config.Encryption.UnsecureDiff, "")
	debugLog(config.Debug, "Finished showDiff")

	return nil
}

// LoadAdditionalRules loads rules from additional rule files specified in command line
func LoadAdditionalRules(config *Config, configDir string, debug bool) ([]Rule, *Config, error) {
	includedRules, err := loadIncludedRules(config.Encryption.IncludeRules, configDir, debug, "additional rules")
	if err != nil {
		return nil, nil, err
	}

	// Check if we found any rules
	if len(includedRules) == 0 {
		debugLog(debug, "No additional rules found in included files")
	} else {
		debugLog(debug, "Loaded %d additional rules from included files", len(includedRules))
	}

	return includedRules, config, nil
}

// ValidateRules validates rules for conflicts
func ValidateRules(rules []Rule, debug bool) error {
	// Basic validation - check for required fields
	for _, rule := range rules {
		if rule.Block == "" {
			return fmt.Errorf("rule '%s' is missing block", rule.Name)
		}
		if rule.Pattern == "" {
			return fmt.Errorf("rule '%s' is missing pattern", rule.Name)
		}
	}

	// Check for duplicate rules
	if duplicates := checkDuplicateRules(rules, debug); len(duplicates) > 0 {
		// If in debug mode, log all duplicates but still return an error for the first one
		if debug {
			for _, dup := range duplicates {
				debugLog(debug, "[WARN] Duplicate rule found: %s", dup)
			}
		}
		// Return first duplicate as error
		return fmt.Errorf("rule conflict detected: %s", duplicates[0])
	}

	return nil
}
