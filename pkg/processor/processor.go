package processor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"gopkg.in/yaml.v3"
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

	// Protect folded style sections before parsing
	_, protectedContent := protectFoldedStyleSections(content, debug)

	var node yaml.Node
	if err := yaml.Unmarshal(protectedContent, &node); err != nil {
		return nil, fmt.Errorf("error parsing YAML: %w", err)
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
		return nil, fmt.Errorf("error parsing YAML: %w", err)
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

// LoadRules loads encryption rules from a config file (exported version)
func LoadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	return loadRules(configFile, debug)
}

// loadRules loads encryption rules from a config file
func loadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	configFile = resolveConfigPath(configFile, debug)

	debugLog(debug, "[loadRules] Config file is: '%s'", configFile)

	config, err := readAndParseConfig(configFile, debug)
	if err != nil {
		return nil, nil, err
	}

	allRules := config.Encryption.Rules

	includedRules, err := processIncludedRules(config, configFile, debug)
	if err != nil {
		return nil, nil, err
	}

	allRules = append(allRules, includedRules...)

	if len(allRules) == 0 {
		debugLog(debug, "Warning: no rules found in main config or included files")
	} else {
		debugLog(debug, "Loaded a total of %d rules", len(allRules))
	}

	config.Encryption.Rules = allRules

	if err := validateRules(config, debug); err != nil {
		return nil, nil, err
	}

	logUnsecureDiffSetting(config, debug)

	config.UnsecureDiff = config.Encryption.UnsecureDiff

	debugLog(debug, "Loaded %d rules in total", len(config.Encryption.Rules))
	return config.Encryption.Rules, config, nil
}

// resolveConfigPath converts relative configFile to absolute if needed
func resolveConfigPath(configFile string, debug bool) string {
	if !filepath.IsAbs(configFile) {
		cwd, err := os.Getwd()
		if err == nil {
			absPath := filepath.Join(cwd, configFile)
			debugLog(debug, "Resolved relative config path '%s' to '%s'", configFile, absPath)
			return absPath
		}
	}
	return configFile
}

// readAndParseConfig reads and parses a YAML config file
func readAndParseConfig(configFile string, debug bool) (*Config, error) {
	content, err := os.ReadFile(configFile) // #nosec G304 - config file path is validated by caller
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return &config, nil
}

// processIncludedRules loads rules from included rule files
func processIncludedRules(config *Config, configFile string, debug bool) ([]Rule, error) {
	if config == nil || len(config.Encryption.IncludeRules) == 0 {
		return nil, nil
	}
	configDir := filepath.Dir(configFile)
	return loadIncludedRules(config.Encryption.IncludeRules, configDir, debug, "included rules")
}

// validateRules validates the loaded rules
func validateRules(config *Config, debug bool) error {
	if config == nil || config.Encryption.ValidateRules == nil || *config.Encryption.ValidateRules {
		return ValidateRules(config.Encryption.Rules, debug)
	}
	return nil
}

// logUnsecureDiffSetting logs a warning if unsecure_diff is enabled
func logUnsecureDiffSetting(config *Config, debug bool) {
	if config.Encryption.UnsecureDiff {
		debugLog(debug, "WARNING: unsecure_diff is set to TRUE...")
	}
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

// ValidateRules validates rules for conflicts
func ValidateRules(rules []Rule, debug bool) error {
	for _, rule := range rules {
		if strings.TrimSpace(rule.Block) == "" {
			return fmt.Errorf("rule '%s' is missing block", rule.Name)
		}
		if strings.TrimSpace(rule.Pattern) == "" {
			return fmt.Errorf("rule '%s' is missing pattern", rule.Name)
		}
		if !isValidRuleAction(rule.Action) {
			return fmt.Errorf("rule '%s' has invalid action", rule.Name)
		}
	}

	if duplicates := checkDuplicateRules(rules, debug); len(duplicates) > 0 {
		return fmt.Errorf("rule conflict detected: %s", duplicates[0])
	}

	return nil
}

// checkDuplicateRules checks for duplicate rules based on name, and on block+pattern+action combination
func checkDuplicateRules(rules []Rule, debug bool) []string {
	var duplicates []string
	ruleMap := make(map[string]map[string]map[string]int) // block -> pattern -> action -> line number
	nameMap := make(map[string]int)                       // rule name -> line number

	for i, rule := range rules {
		action := normalizedRuleAction(rule.Action)
		block := normalizedRuleBlock(rule.Block)
		pattern := normalizedRulePattern(rule.Pattern)
		nameKey := strings.TrimSpace(rule.Name)

		// Check for duplicate rule names
		if previousLine, exists := nameMap[nameKey]; exists {
			// Calculate actual line numbers in YAML file
			duplicateLine := i*linesPerRule + firstRuleOffset
			originalLine := previousLine*linesPerRule + firstRuleOffset
			msg := fmt.Sprintf("Duplicate rule name found: line %d: rule '%s' duplicates rule name at line %d",
				duplicateLine, nameKey, originalLine)
			duplicates = append(duplicates, msg)
		} else {
			nameMap[nameKey] = i
		}

		// Check for duplicate rule configurations (block + pattern + action)
		if _, exists := ruleMap[block]; !exists {
			ruleMap[block] = make(map[string]map[string]int)
		}
		if _, exists := ruleMap[block][pattern]; !exists {
			ruleMap[block][pattern] = make(map[string]int)
		}
		if line, exists := ruleMap[block][pattern][action]; exists {
			// Calculate actual line numbers in YAML file
			duplicateLine := i*linesPerRule + firstRuleOffset
			originalLine := line*linesPerRule + firstRuleOffset
			msg := fmt.Sprintf("Duplicate rule configuration found: line %d: rule '%s' (block: '%s', pattern: '%s', action: '%s') duplicates rule at line %d",
				duplicateLine, rule.Name, block, pattern, action, originalLine)
			duplicates = append(duplicates, msg)
		} else {
			ruleMap[block][pattern][action] = i
		}
	}

	return duplicates
}

// isRuleValidationEnabled returns true if rule validation is enabled
func isRuleValidationEnabled(config *Config) bool {
	return config == nil || config.Encryption.ValidateRules == nil || *config.Encryption.ValidateRules
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

// LoadAdditionalRules loads rules from included rule files
func LoadAdditionalRules(config *Config, configPath string, debug bool) ([]Rule, *Config, error) {
	if config == nil {
		return nil, nil, fmt.Errorf("config cannot be nil")
	}

	// In tests, configPath might be a directory, but in real usage it's a file path
	// Let's use it as configDir if it's already a directory, or get its Dir
	configDir := configPath
	if fileInfo, err := os.Stat(configPath); err == nil && !fileInfo.IsDir() {
		configDir = filepath.Dir(configPath)
	} else if err != nil {
		// If it doesn't exist, assume it was a file path
		configDir = filepath.Dir(configPath)
	}

	includedRules, err := loadIncludedRules(config.Encryption.IncludeRules, configDir, debug, "additional rules")
	if err != nil {
		return nil, nil, err
	}

	return includedRules, config, nil
}
