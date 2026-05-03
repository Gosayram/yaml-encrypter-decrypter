// Package config provides configuration management using Viper.
//
// It supports loading configuration from multiple sources including:
// - Command line flags (highest priority)
// - Environment variables
// - Configuration files
// - Default values (lowest priority)
package config

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	Filename      string
	Key           string
	Operation     string
	DryRun        bool
	Diff          bool
	Debug         bool
	ShowVersion   bool
	Algorithm     string
	Benchmark     bool
	BenchFile     string
	ConfigPath    string
	ValidateRules bool
	IncludeRules  string
	LogLevel      string
	LogFormat     string
	LogOutput     string
}

// Load loads configuration from flags, environment variables, and config file
// This should be called after pflag.Parse()
func Load() (*Config, error) {
	v := viper.New()

	// Set up environment variable prefix
	v.SetEnvPrefix("YED")
	v.AutomaticEnv()

	// Bind environment variables
	if err := v.BindEnv("encryption-key", "ENCRYPTION_KEY"); err != nil {
		return nil, fmt.Errorf("failed to bind environment variable: %w", err)
	}

	// Bind pflags to Viper (flags have highest priority)
	if err := v.BindPFlag("file", pflag.CommandLine.Lookup("file")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("key", pflag.CommandLine.Lookup("key")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("operation", pflag.CommandLine.Lookup("operation")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("dry-run", pflag.CommandLine.Lookup("dry-run")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("diff", pflag.CommandLine.Lookup("diff")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("debug", pflag.CommandLine.Lookup("debug")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("version", pflag.CommandLine.Lookup("version")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("algorithm", pflag.CommandLine.Lookup("algorithm")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("benchmark", pflag.CommandLine.Lookup("benchmark")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("bench-file", pflag.CommandLine.Lookup("bench-file")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("config", pflag.CommandLine.Lookup("config")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("validate", pflag.CommandLine.Lookup("validate")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("include-rules", pflag.CommandLine.Lookup("include-rules")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("log-level", pflag.CommandLine.Lookup("log-level")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("log-format", pflag.CommandLine.Lookup("log-format")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}
	if err := v.BindPFlag("log-output", pflag.CommandLine.Lookup("log-output")); err != nil {
		return nil, fmt.Errorf("failed to bind flag: %w", err)
	}

	// Set defaults (lowest priority)
	v.SetDefault("log-level", "info")
	v.SetDefault("log-format", "console")
	v.SetDefault("log-output", "stderr")

	// Set up config file (env and config file priority: env > config file)
	configPath := v.GetString("config")
	if configPath == "" {
		configPath = ".yed_config.yml"
	}

	// Resolve config path to absolute
	if !filepath.IsAbs(configPath) {
		absPath, err := filepath.Abs(configPath)
		if err == nil {
			configPath = absPath
		}
	}

	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	// Read config file if it exists (optional, not an error if not found)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Create config struct
	cfg := &Config{}

	// Read values from Viper (precedence: flag > env > config file > default)
	cfg.Filename = v.GetString("file")
	cfg.Key = v.GetString("key")
	cfg.Operation = v.GetString("operation")
	cfg.DryRun = v.GetBool("dry-run")
	cfg.Diff = v.GetBool("diff")
	cfg.Debug = v.GetBool("debug")
	cfg.ShowVersion = v.GetBool("version")
	cfg.Algorithm = v.GetString("algorithm")
	cfg.Benchmark = v.GetBool("benchmark")
	cfg.BenchFile = v.GetString("bench-file")
	cfg.ConfigPath = configPath
	cfg.ValidateRules = v.GetBool("validate")
	cfg.IncludeRules = v.GetString("include-rules")
	cfg.LogLevel = v.GetString("log-level")
	cfg.LogFormat = v.GetString("log-format")
	cfg.LogOutput = v.GetString("log-output")

	return cfg, nil
}
