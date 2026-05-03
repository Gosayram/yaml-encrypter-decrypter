package processor

import (
	"fmt"
	"strings"
)

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
		lowered := strings.ToLower(value)
		// Protect sensitive data
		if len(value) > MinEncryptedLength &&
			(strings.Contains(lowered, "password") ||
				strings.Contains(lowered, "key") ||
				strings.Contains(lowered, "yed_encryption_key")) {
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

func normalizedRuleAction(action string) string {
	normalized := strings.ToLower(strings.TrimSpace(action))
	if normalized == "" {
		return ActionEncrypt
	}
	return normalized
}

func normalizedRuleBlock(block string) string {
	return strings.TrimSpace(block)
}

func normalizedRulePattern(pattern string) string {
	return strings.TrimSpace(pattern)
}

func isValidRuleAction(action string) bool {
	switch normalizedRuleAction(action) {
	case ActionEncrypt, ActionNone:
		return true
	default:
		return false
	}
}

func markProcessedPath(processedPaths map[string]bool, path string) {
	if processedPaths == nil {
		return
	}
	processedPaths[path] = true
}
