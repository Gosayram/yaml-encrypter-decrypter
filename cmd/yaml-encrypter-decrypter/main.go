package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/processor"

	"github.com/awnumar/memguard"
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
		log.Println(err)
		flag.Usage()
		return 1
	}

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
			log.Printf("Using custom config path: %s\n", configFilePath)
		}
	}

	// Convert relative path to absolute path
	if !filepath.IsAbs(configFilePath) {
		absPath, err := filepath.Abs(configFilePath)
		if err == nil {
			configFilePath = absPath
			if flags.debug {
				log.Printf("Using absolute config path: %s\n", configFilePath)
			}
		} else {
			log.Printf("Warning: could not convert %s to absolute path: %v\n", configFilePath, err)
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
		log.Println(err)
		flag.Usage()
		return 1
	}

	// Validate required flags
	if flags.filename == "" || key == "" || flags.operation == "" {
		log.Println("Error: filename, key, and operation are required")
		flag.Usage()
		return 1
	}

	// Validate and set algorithm flag if provided
	keyDerivation, err := encryption.ValidateAlgorithm(flags.algorithm)
	if err != nil {
		log.Println(err)
		return 1
	}

	// Create a secure buffer for the key
	keyBuffer := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuffer.Destroy()

	// Load rules from config file
	rules, _, err := processor.LoadRules(configFilePath, flags.debug)
	if err != nil {
		log.Printf("Error loading rules: %v\n", err)
		return 1
	}

	// Process additional rule files if specified
	if flags.includeRules != "" {
		// Parse comma-separated list of rule files.
		additionalRules, err := parseRequiredIncludeRulePatterns(flags.includeRules)
		if err != nil {
			log.Printf("Error: %v\n", err)
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
			log.Printf("Error loading additional rules: %v\n", err)
			return 1
		}

		// Validate combined rules before adding them
		allRules := make([]processor.Rule, len(rules))
		copy(allRules, rules)
		allRules = append(allRules, additionalRulesLoaded...)
		if err := processor.ValidateRules(allRules, flags.debug); err != nil {
			log.Printf("Error validating combined rules: %v\n", err)
			return 1
		}

		// Add additional rules to the existing rules
		rules = append(rules, additionalRulesLoaded...)

		if flags.debug {
			log.Printf("Added %d additional rules from command line\n", len(additionalRulesLoaded))
		}
	}

	// Set the encryption algorithm if specified
	if keyDerivation != "" {
		encryption.SetDefaultAlgorithm(keyDerivation)
	}

	// Process file and handle interruption
	return processFileWithInterruptHandling(flags, keyBuffer, rules)
}

// validateConfiguration validates the configuration file and all included rule files
func validateConfiguration(configPath string, debug bool, includeRulePatterns string) int {
	log.Printf("Validating configuration file: %s\n", configPath)

	// Attempt to load rules which will validate the configuration
	rules, config, err := processor.LoadRules(configPath, debug)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return 1
	}

	// Output validation success
	if len(rules) == 0 {
		log.Printf("Warning: No rules found in configuration. No encryption/decryption will be performed.\n")
	} else {
		log.Printf("Configuration is valid.\n")
		log.Printf("Total rules loaded: %d\n", len(rules))
	}

	// If include_rules is specified in config, show details
	if len(config.Encryption.IncludeRules) > 0 {
		log.Printf("External rule files included in config: %d\n", len(config.Encryption.IncludeRules))
		for _, pattern := range config.Encryption.IncludeRules {
			log.Printf("  - %s\n", pattern)
		}
	}

	// Process additional rule files from command line if specified
	if includeRulePatterns != "" {
		log.Printf("Processing additional rule files from command line: %s\n", includeRulePatterns)

		// Parse comma-separated list of rule files.
		additionalRules, err := parseRequiredIncludeRulePatterns(includeRulePatterns)
		if err != nil {
			log.Printf("Error: %v\n", err)
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
			log.Printf("Error loading additional rules: %v\n", err)
			return 1
		}

		// Validate combined rules
		allRules := make([]processor.Rule, len(rules))
		copy(allRules, rules)
		allRules = append(allRules, additionalRulesLoaded...)
		if err := processor.ValidateRules(allRules, debug); err != nil {
			log.Printf("Error validating combined rules: %v\n", err)
			return 1
		}

		log.Printf("Added %d additional rules from command line\n", len(additionalRulesLoaded))
		for _, pattern := range additionalRules {
			log.Printf("  - %s\n", pattern)
		}
	}

	// Display unsecure_diff setting
	log.Printf("Unsecure diff mode: %v\n", config.Encryption.UnsecureDiff)

	return 0
}
