package processor

import (
	"fmt"
	"strings"
)

// ValidateRules validates rules for conflicts
func ValidateRules(rules []Rule, debug bool) error {
	for _, rule := range rules {
		if strings.TrimSpace(rule.Block) == "" {
			return &ValidationError{
				RuleName: rule.Name,
				Field:    "block",
				Reason:   "missing block",
			}
		}
		if strings.TrimSpace(rule.Pattern) == "" {
			return &ValidationError{
				RuleName: rule.Name,
				Field:    "pattern",
				Reason:   "missing pattern",
			}
		}
		if !isValidRuleAction(rule.Action) {
			return &ValidationError{
				RuleName: rule.Name,
				Field:    "action",
				Reason:   "invalid action",
			}
		}
	}

	if duplicates := checkDuplicateRules(rules, debug); len(duplicates) > 0 {
		return &RuleConflictError{
			Conflict: duplicates[0],
		}
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
