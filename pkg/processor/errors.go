package processor

import "fmt"

// Error types for domain-specific errors

// ValidationError represents a rule validation error
type ValidationError struct {
	RuleName string
	Field    string
	Reason   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("rule '%s' is %s", e.RuleName, e.Reason)
}

// RuleConflictError represents a duplicate rule conflict
type RuleConflictError struct {
	Conflict string
}

func (e *RuleConflictError) Error() string {
	return fmt.Sprintf("rule conflict detected: %s", e.Conflict)
}

// ConfigError represents a configuration loading error
type ConfigError struct {
	Path string
	Err  error
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("config error: %s: %v", e.Path, e.Err)
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

// ProcessingError represents a YAML processing error
type ProcessingError struct {
	Path string
	Err  error
}

func (e *ProcessingError) Error() string {
	return fmt.Sprintf("processing error at %s: %v", e.Path, e.Err)
}

func (e *ProcessingError) Unwrap() error {
	return e.Err
}

// NodeError represents a YAML node processing error
type NodeError struct {
	Path string
	Line int
	Err  error
}

func (e *NodeError) Error() string {
	return fmt.Sprintf("node error at %s (line %d): %v", e.Path, e.Line, e.Err)
}

func (e *NodeError) Unwrap() error {
	return e.Err
}
