package processor

// RuleMatcher defines the interface for matching paths against rules
type RuleMatcher interface {
	// Matches returns true if the given path matches the rule
	Matches(path string, rule Rule, debug bool) bool
}

// DefaultRuleMatcher is the default implementation of RuleMatcher
type DefaultRuleMatcher struct{}

// Matches checks if a path matches a rule using the default matching logic
func (m *DefaultRuleMatcher) Matches(path string, rule Rule, debug bool) bool {
	return matchesRule(path, rule, debug)
}

// NewRuleMatcher creates a new RuleMatcher with the default implementation
func NewRuleMatcher() RuleMatcher {
	return &DefaultRuleMatcher{}
}

// globalRuleMatcher is the default instance used throughout the package
var globalRuleMatcher = NewRuleMatcher()

// SetRuleMatcher sets the global rule matcher (useful for testing)
func SetRuleMatcher(matcher RuleMatcher) {
	globalRuleMatcher = matcher
}

// GetRuleMatcher returns the current global rule matcher
func GetRuleMatcher() RuleMatcher {
	return globalRuleMatcher
}
