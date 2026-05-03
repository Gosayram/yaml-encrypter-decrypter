package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/logger"
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/processor"
	"github.com/awnumar/memguard"
	"go.uber.org/zap"
)

// Version is set during build time
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

	// Run main code and exit with returned code
	code := mainWithExitCode()

	// Clean up at the end of execution
	memguard.Purge()

	// Exit with the return code
	os.Exit(code)
}

func mainWithExitCode() int {
	// Parse command line arguments
	flags, err := parseFlags()
	if err != nil {
		logger.L().Error("Failed to parse flags", zap.Error(err))
		flag.Usage()
		return 1
	}

	// Initialize logger with configuration
	logCfg := logger.Config{
		Level:       flags.logLevel,
		Development: flags.debug,
		Encoding:    flags.logFormat,
		OutputPath:  flags.logOutput,
	}
	if err := logger.Initialize(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		return 1
	}
	defer func() {
		_ = logger.Sync()
	}()

	logger.L().Info("Application starting",
		zap.String("version", Version),
		zap.Bool("debug", flags.debug),
		zap.String("log_level", flags.logLevel),
		zap.String("log_format", flags.logFormat),
	)

	// Show version if requested
	if flags.showVersion {
		displayVersion()
		return 0
	}

	// Run benchmarks if requested
	if flags.benchmark {
		// If no benchmark file is specified, use console output
		benchFile := flags.benchFile
		return runBenchmarks(benchFile)
	}

	// Determine the config path
	configFilePath := ".yed_config.yml"
	if flags.configPath != "" {
		configFilePath = flags.configPath
		if flags.debug {
			logger.L().Debug("Using custom config path", zap.String("path", configFilePath))
		}
	}

	// Convert relative path to absolute path
	if !filepath.IsAbs(configFilePath) {
		absPath, err := filepath.Abs(configFilePath)
		if err == nil {
			configFilePath = absPath
			if flags.debug {
				logger.L().Debug("Using absolute config path", zap.String("path", configFilePath))
			}
		} else {
			logger.L().Warn("Could not convert to absolute path",
				zap.String("path", configFilePath),
				zap.Error(err))
		}
	}

	// Update flags.configPath with the resolved path
	flags.configPath = configFilePath

	// If validate option is specified, validate the configuration and exit
	if flags.validateRules {
		return validateConfiguration(configFilePath, flags.debug, flags.includeRules)
	}

	// Get encryption key (from flag or environment)
	key, err := getEncryptionKey(flags.key, flags.debug)
	if err != nil {
		logger.L().Error("Failed to get encryption key", zap.Error(err))
		flag.Usage()
		return 1
	}

	// Validate required flags
	if flags.filename == "" || key == "" || flags.operation == "" {
		logger.L().Error("Missing required arguments",
			zap.String("filename", flags.filename),
			zap.Bool("has_key", key != ""),
			zap.String("operation", flags.operation))
		flag.Usage()
		return 1
	}

	// Validate and set algorithm flag if provided
	keyDerivation, err := encryption.ValidateAlgorithm(flags.algorithm)
	if err != nil {
		logger.L().Error("Invalid algorithm", zap.String("algorithm", flags.algorithm), zap.Error(err))
		return 1
	}

	// Create a secure buffer for the key
	keyBuffer := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuffer.Destroy()

	// Load rules from config file
	rules, _, err := processor.LoadRules(configFilePath, flags.debug)
	if err != nil {
		logger.L().Error("Failed to load rules", zap.String("config", configFilePath), zap.Error(err))
		return 1
	}

	// Process additional rule files if specified
	if flags.includeRules != "" {
		// Parse comma-separated list of rule files.
		additionalRules, err := parseRequiredIncludeRulePatterns(flags.includeRules)
		if err != nil {
			logger.L().Error("Invalid include rules pattern", zap.String("pattern", flags.includeRules), zap.Error(err))
			return 1
		}

		// Create a temporary YAML file with the include_rules section
		tempConfig := processor.Config{}
		tempConfig.Encryption.IncludeRules = additionalRules
		validateRules := true
		tempConfig.Encryption.ValidateRules = &validateRules

		// Try to load the additional rule files
		additionalRulesLoaded, _, err := processor.LoadAdditionalRules(&tempConfig, filepath.Dir(configFilePath), flags.debug)
		if err != nil {
			logger.L().Error("Failed to load additional rules", zap.Error(err))
			return 1
		}

		// Validate combined rules before adding them
		allRules := make([]processor.Rule, len(rules))
		copy(allRules, rules)
		allRules = append(allRules, additionalRulesLoaded...)
		if err := processor.ValidateRules(allRules, flags.debug); err != nil {
			logger.L().Error("Failed to validate combined rules", zap.Error(err))
			return 1
		}

		// Add additional rules to the existing rules
		rules = append(rules, additionalRulesLoaded...)

		if flags.debug {
			logger.L().Debug("Added additional rules from command line",
				zap.Int("count", len(additionalRulesLoaded)),
				zap.Strings("patterns", additionalRules))
		}
	}

	// Set the encryption algorithm if specified
	if keyDerivation != "" {
		encryption.SetDefaultAlgorithm(keyDerivation)
		logger.L().Info("Key derivation algorithm set", zap.String("algorithm", string(keyDerivation)))
	}

	// Process file and handle interruption
	return processFileWithInterruptHandling(flags, keyBuffer, rules)
}

// validateConfiguration validates the configuration file and all included rule files
func validateConfiguration(configPath string, debug bool, includeRulePatterns string) int {
	logger.L().Info("Validating configuration", zap.String("path", configPath))

	// Attempt to load rules which will validate the configuration
	rules, config, err := processor.LoadRules(configPath, debug)
	if err != nil {
		logger.L().Error("Failed to load configuration", zap.String("path", configPath), zap.Error(err))
		return 1
	}

	// Output validation success
	if len(rules) == 0 {
		logger.L().Warn("No rules found in configuration")
	} else {
		logger.L().Info("Configuration is valid",
			zap.Int("rules_count", len(rules)))
	}

	// If include_rules is specified in config, show details
	if len(config.Encryption.IncludeRules) > 0 {
		logger.L().Info("External rule files included in config",
			zap.Int("count", len(config.Encryption.IncludeRules)),
			zap.Strings("patterns", config.Encryption.IncludeRules))
	}

	// Process additional rule files from command line if specified
	if includeRulePatterns != "" {
		logger.L().Info("Processing additional rule files from command line", zap.String("patterns", includeRulePatterns))

		// Parse comma-separated list of rule files.
		additionalRules, err := parseRequiredIncludeRulePatterns(includeRulePatterns)
		if err != nil {
			logger.L().Error("Invalid include rules pattern", zap.String("pattern", includeRulePatterns), zap.Error(err))
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
			logger.L().Error("Failed to load additional rules", zap.Error(err))
			return 1
		}

		// Validate combined rules
		allRules := make([]processor.Rule, len(rules))
		copy(allRules, rules)
		allRules = append(allRules, additionalRulesLoaded...)
		if err := processor.ValidateRules(allRules, debug); err != nil {
			logger.L().Error("Failed to validate combined rules", zap.Error(err))
			return 1
		}

		logger.L().Info("Added additional rules from command line",
			zap.Int("count", len(additionalRulesLoaded)),
			zap.Strings("patterns", additionalRules))
	}

	// Display unsecure_diff setting
	logger.L().Info("Unsecure diff mode", zap.Bool("enabled", config.Encryption.UnsecureDiff))

	return 0
}
