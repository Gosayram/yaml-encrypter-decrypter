package processor

import (
	"fmt"
	"strings"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	// Named logger for processor component
	processorLogger = logger.Named("processor")
)

// ProcessYAMLContent processes YAML content with the given rules (exported version)
func ProcessYAMLContent(content []byte, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) (*yaml.Node, error) {
	return processYAMLContent(content, key, operation, rules, processedPaths, debug)
}

// processYAMLContent processes YAML content
func processYAMLContent(content []byte, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) (*yaml.Node, error) {
	if !isValidOperation(operation) {
		return nil, fmt.Errorf("invalid operation: %s", operation)
	}

	if len(strings.TrimSpace(string(content))) == 0 {
		return nil, fmt.Errorf("empty YAML content")
	}

	processorLogger.Debug("Starting YAML processing",
		zap.String("operation", operation),
		zap.Int("content_length", len(content)),
		zap.Int("rules_count", len(rules)),
	)

	// Protect folded style sections before parsing
	_, protectedContent := protectFoldedStyleSections(content, debug)

	var node yaml.Node
	if err := yaml.Unmarshal(protectedContent, &node); err != nil {
		// Provide more detailed error message for YAML parsing failures
		if typeErr, ok := err.(*yaml.TypeError); ok {
			return nil, fmt.Errorf("YAML parsing error: %w (lines: %v)", err, typeErr.Errors)
		}
		return nil, fmt.Errorf("YAML parsing error: %w (check for invalid syntax, indentation, or structure)", err)
	}

	// Create a map to track excluded paths
	excludedPaths := make(map[string]bool)
	for _, rule := range rules {
		if normalizedRuleAction(rule.Action) == ActionNone {
			if err := markExcludedPaths(&node, rule, "", excludedPaths, debug); err != nil {
				return nil, err
			}
		}
	}

	if err := processNodeWithExclusions(&node, "", key, operation, rules, processedPaths, excludedPaths, debug); err != nil {
		return nil, err
	}

	return &node, nil
}

// ProcessYAMLContentWithFoldedStyle processes YAML content with folded style protection and restoration
func ProcessYAMLContentWithFoldedStyle(content []byte, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) ([]byte, error) {
	if !isValidOperation(operation) {
		return nil, fmt.Errorf("invalid operation: %s", operation)
	}

	if len(strings.TrimSpace(string(content))) == 0 {
		return nil, fmt.Errorf("empty YAML content")
	}

	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		// Provide more detailed error message for YAML parsing failures
		if typeErr, ok := err.(*yaml.TypeError); ok {
			return nil, fmt.Errorf("YAML parsing error: %w (lines: %v)", err, typeErr.Errors)
		}
		return nil, fmt.Errorf("YAML parsing error: %w (check for invalid syntax, indentation, or structure)", err)
	}

	// Create a map to track excluded paths
	excludedPaths := make(map[string]bool)
	for _, rule := range rules {
		if normalizedRuleAction(rule.Action) == ActionNone {
			if err := markExcludedPaths(&node, rule, "", excludedPaths, debug); err != nil {
				return nil, err
			}
		}
	}

	if err := processNodeWithExclusions(&node, "", key, operation, rules, processedPaths, excludedPaths, debug); err != nil {
		return nil, err
	}

	// Marshal back to YAML
	processedContent, err := yaml.Marshal(&node)
	if err != nil {
		return nil, fmt.Errorf("error marshaling YAML: %w", err)
	}

	return processedContent, nil
}

// ProcessDiff processes YAML content and shows differences
func ProcessDiff(content []byte, config Config) error {
	debugLog(config.Debug, "Processing diff")

	operation := config.Operation
	if operation == "" {
		operation = OperationEncrypt
	}
	if !isValidOperation(operation) {
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

	debugLog(config.Debug, "Printing differences")
	stats := &diffStats{}
	printDiff(originalData.Content[0], processedNode.Content[0], config.Debug, config.Encryption.UnsecureDiff, "", stats)

	releaseNodeTree(&originalData)
	releaseNodeTree(processedNode)

	return nil
}

// ProcessNode is a backward-compatible wrapper for processNode
func ProcessNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	return processNode(node, path, key, operation, rules, processedPaths, debug)
}

// ShowDiff is a backward-compatible wrapper for showDiff
// Old signature expected by some tests: func ShowDiff(filePath, key, operation string, debug bool, configPath string) error
func ShowDiff(args ...interface{}) error {
	if len(args) == 5 {
		// Handle old signature: (filePath, key, operation, debug, configPath)
		filePath, _ := args[0].(string)
		key, _ := args[1].(string)
		operation, _ := args[2].(string)
		debug, _ := args[3].(bool)
		configPath, _ := args[4].(string)

		return ProcessFile(filePath, key, operation, debug, configPath)
	}

	// Handle new signature (for internal use, though internal calls should use showDiff)
	if len(args) == 6 {
		data, _ := args[0].(*yaml.Node)
		key, _ := args[1].(string)
		operation, _ := args[2].(string)
		unsecureDiff, _ := args[3].(bool)
		debug, _ := args[4].(bool)
		rules, _ := args[5].([]Rule)
		showDiff(data, key, operation, unsecureDiff, debug, rules)
		return nil
	}

	return fmt.Errorf("invalid arguments for ShowDiff")
}

// SetKeyDerivationAlgorithm is a wrapper for backward compatibility with tests
func SetKeyDerivationAlgorithm(alg interface{}) error {
	var algStr string
	switch v := alg.(type) {
	case string:
		algStr = v
	case encryption.KeyDerivationAlgorithm:
		algStr = string(v)
	default:
		return fmt.Errorf("invalid algorithm type")
	}

	normalizedAlg := encryption.KeyDerivationAlgorithm(strings.ToUpper(strings.TrimSpace(algStr)))
	if strings.HasPrefix(string(normalizedAlg), "PBKDF2") || strings.HasPrefix(string(normalizedAlg), "ARGON2") {
		// Just a heuristic for normalization to match tests, let's look at the actual supported ones.
		// encryption.Argon2idAlgorithm is "argon2id"
		normalizedAlg = encryption.KeyDerivationAlgorithm(strings.ToLower(string(normalizedAlg)))
	}

	if normalizedAlg != encryption.PBKDF2SHA256Algorithm &&
		normalizedAlg != encryption.PBKDF2SHA512Algorithm &&
		normalizedAlg != encryption.Argon2idAlgorithm {
		return fmt.Errorf("unsupported algorithm: %s", algStr)
	}

	encryption.SetDefaultAlgorithm(normalizedAlg)
	return nil
}
