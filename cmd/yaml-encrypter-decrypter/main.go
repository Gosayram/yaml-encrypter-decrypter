package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/config"
	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/logger"
	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/processor"
	"github.com/awnumar/memguard"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

var (
	// Named logger for the main application
	mainLogger = logger.Named("app")
)

// Version is set during build time and should be in the format "major.minor"
var Version = "dev"

const (
	// VersionParts is the number of parts in version string
	VersionParts = 2
)

func parseIncludeRulePatterns(input string) []string {
	if strings.TrimSpace(input) == "" {
		return nil
	}

	rawPatterns := strings.Split(input, ",")
	patterns := make([]string, 0, len(rawPatterns))
	for _, pattern := range rawPatterns {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			continue
		}
		patterns = append(patterns, trimmed)
	}
	if len(patterns) == 0 {
		return nil
	}
	return patterns
}

func parseRequiredIncludeRulePatterns(input string) ([]string, error) {
	patterns := parseIncludeRulePatterns(input)
	if len(patterns) == 0 {
		return nil, fmt.Errorf("include-rules provided, but no valid rule file patterns were found")
	}
	return patterns, nil
}

func main() {
	// Safe termination when receiving interrupt signal
	memguard.CatchInterrupt()

	// Initialize flags
	initFlags()

	// Run the main application logic
	code := mainWithExitCode()

	// Clean up at the end of execution
	memguard.Purge()

	// Exit with the return code
	os.Exit(code)
}

func mainWithExitCode() int {
	// Parse command line arguments using pflag
	pflag.Parse()

	// Load configuration from flags, environment variables, and config file
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		pflag.Usage()
		return 1
	}

	// Initialize logger with configuration
	logCfg := logger.Config{
		Level:       cfg.LogLevel,
		Development: cfg.Debug,
		Encoding:    cfg.LogFormat,
		OutputPath:  cfg.LogOutput,
	}
	if err := logger.Initialize(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		return 1
	}
	defer func() {
		_ = logger.Sync()
	}()

	mainLogger.Info("Application starting",
		zap.String("version", Version),
		zap.Bool("debug", cfg.Debug),
		zap.String("log_level", cfg.LogLevel),
		zap.String("log_format", cfg.LogFormat),
	)

	// Show version if requested
	if cfg.ShowVersion {
		displayVersion()
		return 0
	}

	// Run benchmarks if requested
	if cfg.Benchmark {
		return runBenchmarks(cfg.BenchFile)
	}

	// If validate option is specified, validate the configuration and exit
	if cfg.ValidateRules {
		return validateConfiguration(cfg.ConfigPath, cfg.Debug, cfg.IncludeRules)
	}

	// Get encryption key (from flag or environment)
	key, err := getEncryptionKey(cfg.Key, cfg.Debug)
	if err != nil {
		mainLogger.Error("Failed to get encryption key", zap.Error(err))
		pflag.Usage()
		return 1
	}

	// Validate required flags
	if cfg.Filename == "" || key == "" || cfg.Operation == "" {
		mainLogger.Error("Missing required arguments",
			zap.String("filename", cfg.Filename),
			zap.Bool("has_key", key != ""),
			zap.String("operation", cfg.Operation))
		pflag.Usage()
		return 1
	}

	// Validate and set algorithm flag if provided
	keyDerivation, err := encryption.ValidateAlgorithm(cfg.Algorithm)
	if err != nil {
		mainLogger.Error("Invalid algorithm", zap.String("algorithm", cfg.Algorithm), zap.Error(err))
		return 1
	}

	// Create a secure buffer for the key
	keyBuffer := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuffer.Destroy()

	// Load rules from config file
	rules, _, err := processor.LoadRules(cfg.ConfigPath, cfg.Debug)
	if err != nil {
		mainLogger.Error("Failed to load rules", zap.String("config", cfg.ConfigPath), zap.Error(err))
		return 1
	}

	// Process additional rule files if specified
	if cfg.IncludeRules != "" {
		additionalRules, err := parseRequiredIncludeRulePatterns(cfg.IncludeRules)
		if err != nil {
			mainLogger.Error("Invalid include rules pattern", zap.String("pattern", cfg.IncludeRules), zap.Error(err))
			return 1
		}

		tempConfig := processor.Config{}
		tempConfig.Encryption.IncludeRules = additionalRules
		validateRules := true
		tempConfig.Encryption.ValidateRules = &validateRules

		additionalRulesLoaded, _, err := processor.LoadAdditionalRules(&tempConfig, filepath.Dir(cfg.ConfigPath), cfg.Debug)
		if err != nil {
			mainLogger.Error("Failed to load additional rules", zap.Error(err))
			return 1
		}

		allRules := make([]processor.Rule, len(rules))
		copy(allRules, rules)
		allRules = append(allRules, additionalRulesLoaded...)
		if err := processor.ValidateRules(allRules, cfg.Debug); err != nil {
			mainLogger.Error("Failed to validate combined rules", zap.Error(err))
			return 1
		}

		rules = append(rules, additionalRulesLoaded...)

		if cfg.Debug {
			mainLogger.Debug("Added additional rules from command line",
				zap.Int("count", len(additionalRulesLoaded)),
				zap.Strings("patterns", additionalRules))
		}
	}

	if keyDerivation != "" {
		encryption.SetDefaultAlgorithm(keyDerivation)
		mainLogger.Info("Key derivation algorithm set", zap.String("algorithm", string(keyDerivation)))
	}

	// Convert config to appFlags for compatibility
	flags := appFlags{
		filename:   cfg.Filename,
		key:        key,
		operation:  cfg.Operation,
		dryRun:     cfg.DryRun,
		diff:       cfg.Diff,
		debug:      cfg.Debug,
		algorithm:  cfg.Algorithm,
		configPath: cfg.ConfigPath,
	}

	return processFileWithInterruptHandling(flags, keyBuffer, rules)
}

// validateConfiguration validates the configuration file and all included rule files
func validateConfiguration(configPath string, debug bool, includeRulePatterns string) int {
	mainLogger.Info("Validating configuration", zap.String("path", configPath))

	// Attempt to load rules which will validate the configuration
	rules, config, err := processor.LoadRules(configPath, debug)
	if err != nil {
		mainLogger.Error("Failed to load configuration", zap.String("path", configPath), zap.Error(err))
		return 1
	}

	// Output validation success
	if len(rules) == 0 {
		mainLogger.Warn("No rules found in configuration")
	} else {
		mainLogger.Info("Configuration is valid",
			zap.Int("rules_count", len(rules)))
	}

	// If include_rules is specified in config, show details
	if len(config.Encryption.IncludeRules) > 0 {
		mainLogger.Info("External rule files included in config",
			zap.Int("count", len(config.Encryption.IncludeRules)),
			zap.Strings("patterns", config.Encryption.IncludeRules))
	}

	// Process additional rule files from command line if specified
	if includeRulePatterns != "" {
		mainLogger.Info("Processing additional rule files from command line", zap.String("patterns", includeRulePatterns))

		// Parse comma-separated list of rule files.
		additionalRules, err := parseRequiredIncludeRulePatterns(includeRulePatterns)
		if err != nil {
			mainLogger.Error("Invalid include rules pattern", zap.String("pattern", includeRulePatterns), zap.Error(err))
			return 1
		}

		// Create a temporary YAML file with the include_rules section
		tempConfig := processor.Config{}
		tempConfig.Encryption.IncludeRules = additionalRules
		validateRules := true
		tempConfig.Encryption.ValidateRules = &validateRules

		// Try to load the additional rule files
		additionalRulesLoaded, _, err := processor.LoadAdditionalRules(&tempConfig, filepath.Dir(configPath), debug)
		if err != nil {
			mainLogger.Error("Failed to load additional rules", zap.Error(err))
			return 1
		}

		// Validate combined rules
		allRules := make([]processor.Rule, len(rules))
		copy(allRules, rules)
		allRules = append(allRules, additionalRulesLoaded...)
		if err := processor.ValidateRules(allRules, debug); err != nil {
			mainLogger.Error("Failed to validate combined rules", zap.Error(err))
			return 1
		}

		mainLogger.Info("Added additional rules from command line",
			zap.Int("count", len(additionalRulesLoaded)),
			zap.Strings("patterns", additionalRules))
	}

	// Display unsecure_diff setting
	mainLogger.Info("Unsecure diff mode", zap.Bool("enabled", config.Encryption.UnsecureDiff))

	return 0
}
