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
	"strings"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/logger"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

// Config holds the application configuration
type Config struct {
	Filename      string `mapstructure:"file"`
	Key           string `mapstructure:"key"`
	Operation     string `mapstructure:"operation"`
	DryRun        bool   `mapstructure:"dry-run"`
	Diff          bool   `mapstructure:"diff"`
	Debug         bool   `mapstructure:"debug"`
	ShowVersion   bool   `mapstructure:"version"`
	Algorithm     string `mapstructure:"algorithm"`
	Benchmark     bool   `mapstructure:"benchmark"`
	BenchFile     string `mapstructure:"bench-file"`
	ConfigPath    string `mapstructure:"config"`
	ValidateRules bool   `mapstructure:"validate"`
	IncludeRules  string `mapstructure:"include-rules"`
	LogLevel      string `mapstructure:"log-level"`
	LogFormat     string `mapstructure:"log-format"`
	LogOutput     string `mapstructure:"log-output"`
}

// Load loads configuration from flags, environment variables, and config file
// This should be called after pflag.Parse()
func Load() (*Config, error) {
	v := viper.New()

	// Set up environment variable prefix
	v.SetEnvPrefix("YED")
	v.AutomaticEnv()

	// Set up environment variable key replacer to allow env vars with underscores
	// to map to config keys with hyphens (e.g., YED_LOG_LEVEL -> log-level)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Bind environment variables
	var bindErr error
	if err := v.BindEnv("encryption-key", "ENCRYPTION_KEY"); err != nil {
		bindErr = multierr.Append(bindErr, fmt.Errorf("failed to bind environment variable: %w", err))
	}

	// Bind pflags to Viper (flags have highest priority)
	flagBindings := []struct {
		key  string
		flag string
	}{
		{"file", "file"},
		{"key", "key"},
		{"operation", "operation"},
		{"dry-run", "dry-run"},
		{"diff", "diff"},
		{"debug", "debug"},
		{"version", "version"},
		{"algorithm", "algorithm"},
		{"benchmark", "benchmark"},
		{"bench-file", "bench-file"},
		{"config", "config"},
		{"validate", "validate"},
		{"include-rules", "include-rules"},
		{"log-level", "log-level"},
		{"log-format", "log-format"},
		{"log-output", "log-output"},
		{"log-level", "l"},
		{"log-format", "F"},
		{"log-output", "O"},
	}

	for _, binding := range flagBindings {
		if err := v.BindPFlag(binding.key, pflag.CommandLine.Lookup(binding.flag)); err != nil {
			bindErr = multierr.Append(bindErr, fmt.Errorf("failed to bind flag %s: %w", binding.flag, err))
		}
	}

	if bindErr != nil {
		return nil, bindErr
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

	// Watch config file for changes (optional, won't error if file doesn't exist)
	// This allows hot-reloading of configuration without restarting the application
	v.WatchConfig()

	// Unmarshal config into struct using mapstructure tags
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set ConfigPath separately since it's not in the config file
	cfg.ConfigPath = configPath

	// Log configuration source information for debugging
	if v.IsSet("file") {
		logger.L().Debug("file flag explicitly set", zap.String("file", cfg.Filename))
	}
	if v.IsSet("key") {
		logger.L().Debug("key flag explicitly set (from flag or env)")
	}
	if v.IsSet("config") {
		logger.L().Debug("config file explicitly set", zap.String("config", cfg.ConfigPath))
	}

	return cfg, nil
}

// AllSettings returns all settings for debugging purposes
func AllSettings() map[string]interface{} {
	v := viper.GetViper()
	if v == nil {
		return nil
	}
	return v.AllSettings()
}

// GetSubConfig extracts a nested configuration subtree for a specific component
// This is useful for organizing complex configurations and passing component-specific settings
func GetSubConfig(key string) (*viper.Viper, error) {
	v := viper.GetViper()
	if v == nil {
		return nil, fmt.Errorf("viper instance is nil")
	}

	sub := v.Sub(key)
	if sub == nil {
		return nil, fmt.Errorf("sub-config key '%s' not found", key)
	}

	return sub, nil
}
