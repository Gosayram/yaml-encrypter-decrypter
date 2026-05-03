package processor

import (
	"fmt"
	"strings"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/encryption"
	"gopkg.in/yaml.v3"
)

// processNodeWithExclusions processes a node with path exclusions
func processNodeWithExclusions(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, excludedPaths map[string]bool, debug bool) error {
	if !isValidOperation(operation) {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	if node == nil {
		return nil
	}

	// Check if this path should be excluded
	if excludedPaths[path] {
		debugLog(debug, "Skipping excluded path: %s", path)
		return nil
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := processNodeWithExclusions(child, path, key, operation, rules, processedPaths, excludedPaths, debug); err != nil {
				return err
			}
		}
		return nil
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
	markProcessedPath(processedPaths, path)

	// Check whether any rule applies before doing style-specific processing.
	ruleName, canApply := processRules(path, rules, debug)
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
	return processScalarNodeStandardWithRule(node, path, operation, key, ruleName, canApply, debug)
}

// processScalarNodeStandard processes a scalar node for encryption or decryption
func processScalarNodeStandard(node *yaml.Node, path string, operation string, key string, rules []Rule, debug bool) error {
	ruleName, canApply := processRules(path, rules, debug)
	return processScalarNodeStandardWithRule(node, path, operation, key, ruleName, canApply, debug)
}

func processScalarNodeStandardWithRule(node *yaml.Node, path string, operation string, key string, ruleName string, canApply bool, debug bool) error {
	// Check for valid operation
	if !isValidOperation(operation) {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	// Keep backward-compatible weak-key error semantics for obviously short keys.
	if len(key) < minKeyLengthGuard {
		return fmt.Errorf("key is too weak: length should be at least %d characters", minKeyLengthGuard)
	}

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

// processNode processes a node
func processNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	if !isValidOperation(operation) {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := processNode(child, path, key, operation, rules, processedPaths, debug); err != nil {
				return err
			}
		}
		return nil
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

// processMappingNode processes a mapping node
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

// processSequenceNode processes a sequence node
func processSequenceNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		newPath := fmt.Sprintf("%s[%d]", path, i)
		if err := processNode(item, newPath, key, operation, rules, processedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

// processScalarNode processes a scalar node
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

// processMultilineStyleNode processes a multiline node
func processMultilineStyleNode(node *yaml.Node, path string, key, operation string, processedPaths map[string]bool, debug bool) error {
	debugLog(debug, "Using multiline processor for %s style node at path %s", GetStyleName(node.Style), path)
	processed, err := ProcessMultilineNode(node, path, key, operation, debug)
	if err != nil {
		return err
	}
	if processed {
		debugLog(debug, "Multiline node at path %s was processed successfully", path)
		markProcessedPath(processedPaths, path)
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

	initialStyle := node.Style

	debugLog(debug, "Encrypting value at path %s", path)
	encryptedValue, err := encryption.Encrypt(key, node.Value)
	if err != nil {
		return fmt.Errorf("error encrypting value at path %s: %v", path, err)
	}

	styleSuffix := getStyleSuffix(initialStyle)
	if styleSuffix != "|plain" {
		encryptedValue += styleSuffix
		debugLog(debug, "Added style suffix %s to encrypted value", styleSuffix)
	}

	node.Value = AES + encryptedValue
	debugLog(debug, "Encrypted node with style: %d", initialStyle)
	node.Style = 0

	markProcessedPath(processedPaths, path)
	return nil
}

// decryptScalarNode decrypts a scalar node
func decryptScalarNode(node *yaml.Node, path string, key string, processedPaths map[string]bool, debug bool) error {
	// Skip non-encrypted values
	if !strings.HasPrefix(node.Value, AES) {
		debugLog(debug, "Value at path %s is not encrypted", path)
		return nil
	}

	encrypted := strings.TrimPrefix(node.Value, AES)

	debugLog(debug, "DECRYPT TRACE - Path: %s, AES prefix removed, value length: %d", path, len(encrypted))
	if len(encrypted) > previewEncryptedChars {
		debugLog(debug, "DECRYPT TRACE - First %d chars: '%s'", previewEncryptedChars, encrypted[:previewEncryptedChars])
	} else {
		debugLog(debug, "DECRYPT TRACE - Full value: '%s'", encrypted)
	}

	decryptedValue, err := decryptNodeValue(encrypted, key, debug)
	if err != nil {
		return fmt.Errorf("error decrypting value at path %s: %v", path, err)
	}

	styleInfo := yaml.Style(0)

	for _, styleName := range []string{StyleLiteral, StyleFolded, StyleDoubleQuoted, StyleSingleQuoted, StylePlain} {
		suffix := "|" + styleName
		if strings.HasSuffix(decryptedValue, suffix) {
			decryptedValue = decryptedValue[:len(decryptedValue)-len(suffix)]

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

	node.Value = decryptedValue
	applyNodeStyle(node, styleInfo, debug)

	markProcessedPath(processedPaths, path)
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

	encrypted = cleanMultilineEncrypted(encrypted, debug)
	cleanedEncrypted, styleSuffix := extractStyleSuffix(encrypted, debug)
	encrypted = cleanedEncrypted

	debugLog(debug, "After style suffix extraction, encrypted value length: %d", len(encrypted))

	if len(encrypted) < MinEncryptedLength {
		debugLog(debug, "WARNING: Encrypted value too short (%d bytes), might not be encrypted data: '%s'",
			len(encrypted), encrypted)
		if styleSuffix != "" {
			return encrypted + styleSuffix, nil
		}
		return encrypted, nil
	}

	debugLog(debug, "Calling encryption.DecryptToString with cleaned value...")
	decryptedBuffer, err := encryption.DecryptToString(encrypted, key)
	if err != nil {
		debugLog(debug, "Error decrypting value: %v", err)
		if strings.Contains(err.Error(), "base64") {
			paddedEncrypted := fixBase64Padding(encrypted, debug)
			debugLog(debug, "Retrying with padded Base64 string")
			if decryptedBuffer, err = encryption.DecryptToString(paddedEncrypted, key); err != nil {
				return "", err
			}
			return decryptedBuffer, nil
		}
		return "", err
	}

	if styleSuffix != "" {
		decryptedBuffer += styleSuffix
	}

	logDecryptionResult(decryptedBuffer, debug)
	return decryptedBuffer, nil
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

// markExcludedPaths marks paths that should be excluded based on rules
func markExcludedPaths(node *yaml.Node, rule Rule, currentPath string, excludedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}
	if excludedPaths == nil {
		excludedPaths = make(map[string]bool)
	}

	if currentPath != "" {
		if globalRuleMatcher.Matches(currentPath, rule, debug) {
			debugLog(debug, "Marking path for exclusion based on rule '%s': %s", rule.Name, currentPath)
			excludedPaths[currentPath] = true
		}
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := markExcludedPaths(child, rule, currentPath, excludedPaths, debug); err != nil {
				return err
			}
		}
		return nil
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
	if !isValidOperation(operation) {
		return fmt.Errorf("invalid operation: %s", operation)
	}
	if processedPaths == nil {
		processedPaths = make(map[string]bool)
	}
	if excludedPaths == nil {
		excludedPaths = make(map[string]bool)
	}

	// Check if this path should be excluded
	if excludedPaths[currentPath] {
		debugLog(debug, "Skipping excluded path: %s", currentPath)
		return nil
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := processYAMLWithExclusions(child, key, operation, rule, currentPath, processedPaths, excludedPaths, debug); err != nil {
				return err
			}
		}
		return nil
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
	if !excludedPaths[currentPath] && globalRuleMatcher.Matches(currentPath, rule, debug) {
		debugLog(debug, "Processing scalar node at path: %s", currentPath)

		// Process multiline nodes first
		processed, err := ProcessMultilineNode(node, currentPath, key, operation, debug)
		if err != nil {
			return fmt.Errorf("failed to process multiline node at path %s: %w", currentPath, err)
		}

		if processed {
			markProcessedPath(processedPaths, currentPath)
			debugLog(debug, "Successfully processed multiline node at path %s", currentPath)
			return nil
		}

		markProcessedPath(processedPaths, currentPath)

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
		styleSuffix := getStyleSuffix(node.Style)
		originalValue := node.Value

		encrypted, err := encryption.Encrypt(key, originalValue)
		if err != nil {
			return fmt.Errorf("failed to encrypt value at path %s: %w", currentPath, err)
		}

		node.Value = AES + encrypted + styleSuffix
		node.Style = 0
	}
	return nil
}

// processDecryptionWithExclusions processes a scalar node for decryption with exclusions
func processDecryptionWithExclusions(node *yaml.Node, key, currentPath string, processedPaths map[string]bool, debug bool) error {
	if strings.HasPrefix(node.Value, AES) {
		debugLog(debug, "Processing encrypted node with value: %s", maskEncryptedValue(node.Value, debug, currentPath))
		encrypted := strings.TrimPrefix(node.Value, AES)

		decryptedValue, err := decryptNodeValue(encrypted, key, debug)
		if err != nil {
			return err
		}

		node.Value = decryptedValue
		applyNodeStyle(node, 0, debug)

		markProcessedPath(processedPaths, currentPath)
	}
	return nil
}
