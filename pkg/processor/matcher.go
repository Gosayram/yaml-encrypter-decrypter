package processor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

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
	block := normalizedRuleBlock(rule.Block)
	pattern := normalizedRulePattern(rule.Pattern)
	exclude := strings.TrimSpace(rule.Exclude)

	// Check if block matches before checking the pattern
	if block != "*" && block != "**" {
		// Check if path is exactly a block or starts with a block
		if path != block && !strings.HasPrefix(path, block+".") {
			debugLog(debug, "Path '%s' does not start with or equal to block '%s'", path, block)
			return false
		}
	}

	// Handle special case for pattern being double asterisk
	if pattern == "**" {
		debugLog(debug, "Pattern '**' matches everything")
		return true
	}

	// Split path into parts
	parts := strings.Split(path, ".")

	// For empty path, only match wildcard patterns
	if path == "" {
		return pattern == "*" || pattern == "**"
	}

	// Handle pattern matching on the last part of the path
	var partToMatch string
	if path == block {
		partToMatch = path
	} else {
		if strings.HasPrefix(path, block+".") {
			// Extract the part of the path after the block
			restPath := strings.TrimPrefix(path, block+".")
			// If pattern contains *, apply it to the rest of the path
			if strings.Contains(pattern, "*") {
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
	if !matchesPattern(partToMatch, pattern, debug) {
		debugLog(debug, "Part '%s' does not match pattern '%s'", partToMatch, pattern)
		return false
	}

	// Check exclude pattern if present
	if exclude != "" {
		lastPart := parts[len(parts)-1]
		if matchesPattern(lastPart, exclude, debug) {
			debugLog(debug, "Path '%s' matches exclude pattern '%s'", path, exclude)
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

	// Replace * with .* for single level search
	pattern = strings.ReplaceAll(pattern, "\\*", ".*")

	// Add start and end of string
	return "^" + pattern + "$"
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
		if normalizedRuleAction(rule.Action) == ActionNone && matchesRule(path, rule, debug) {
			debugLog(debug, "Path %s matches 'none' action rule %s - skipping encryption", path, rule.Name)
			return "", false
		}
	}

	// Then check rules with encrypt action
	for _, rule := range rules {
		if normalizedRuleAction(rule.Action) == ActionEncrypt && matchesRule(path, rule, debug) {
			debugLog(debug, "Path %s matches rule %s for encryption", path, rule.Name)
			return rule.Name, true
		}
	}

	debugLog(debug, "No matching rules found for path: %s", path)
	return "", false
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

var includeRangeRegex = regexp.MustCompile(`\[(\d+)-(\d+)\]`)

func isExplicitIncludeRuleFile(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
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
		pattern := strings.TrimSpace(rulePattern)
		if pattern == "" {
			debugLog(debug, "Skipping empty %s pattern entry", label)
			continue
		}

		if isExplicitIncludeRuleFile(pattern) {
			resolvedPattern := resolveIncludePattern(pattern, configDir)
			rules, err := loadRulesFromFile(resolvedPattern, debug)
			if err != nil {
				return nil, fmt.Errorf("failed to load %s from file '%s': %w", label, rulePattern, err)
			}
			includedRules = append(includedRules, rules...)
			continue
		}

		rules, err := loadRulesFromPattern(pattern, configDir, debug)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s from pattern '%s': %w", label, rulePattern, err)
		}
		includedRules = append(includedRules, rules...)
	}

	return includedRules, nil
}
