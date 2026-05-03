package processor

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadRules loads encryption rules from a config file (exported version)
func LoadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	return loadRules(configFile, debug)
}

// loadRules loads encryption rules from a config file
func loadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	configFile = resolveConfigPath(configFile, debug)

	debugLog(debug, "[loadRules] Config file is: '%s'", configFile)

	config, err := readAndParseConfig(configFile, debug)
	if err != nil {
		return nil, nil, err
	}

	allRules := config.Encryption.Rules

	includedRules, err := processIncludedRules(config, configFile, debug)
	if err != nil {
		return nil, nil, err
	}

	allRules = append(allRules, includedRules...)

	if len(allRules) == 0 {
		debugLog(debug, "Warning: no rules found in main config or included files")
	} else {
		debugLog(debug, "Loaded a total of %d rules", len(allRules))
	}

	config.Encryption.Rules = allRules

	if err := validateRules(config, debug); err != nil {
		return nil, nil, err
	}

	logUnsecureDiffSetting(config, debug)

	config.UnsecureDiff = config.Encryption.UnsecureDiff

	debugLog(debug, "Loaded %d rules in total", len(config.Encryption.Rules))
	return config.Encryption.Rules, config, nil
}

// resolveConfigPath converts relative configFile to absolute if needed
func resolveConfigPath(configFile string, debug bool) string {
	if !filepath.IsAbs(configFile) {
		cwd, err := os.Getwd()
		if err == nil {
			absPath := filepath.Join(cwd, configFile)
			debugLog(debug, "Resolved relative config path '%s' to '%s'", configFile, absPath)
			return absPath
		}
	}
	return configFile
}

// readAndParseConfig reads and parses a YAML config file
func readAndParseConfig(configFile string, debug bool) (*Config, error) {
	content, err := os.ReadFile(configFile) // #nosec G304 - config file path is validated by caller
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return &config, nil
}

// processIncludedRules loads rules from included rule files
func processIncludedRules(config *Config, configFile string, debug bool) ([]Rule, error) {
	if config == nil || len(config.Encryption.IncludeRules) == 0 {
		return nil, nil
	}
	configDir := filepath.Dir(configFile)
	return loadIncludedRules(config.Encryption.IncludeRules, configDir, debug, "included rules")
}

// validateRules validates the loaded rules based on config settings
func validateRules(config *Config, debug bool) error {
	if config == nil || config.Encryption.ValidateRules == nil || *config.Encryption.ValidateRules {
		return ValidateRules(config.Encryption.Rules, debug)
	}
	return nil
}

// logUnsecureDiffSetting logs a warning if unsecure_diff is enabled
func logUnsecureDiffSetting(config *Config, debug bool) {
	if config.Encryption.UnsecureDiff {
		debugLog(debug, "WARNING: unsecure_diff is set to TRUE...")
	}
}

// LoadAdditionalRules loads rules from included rule files
func LoadAdditionalRules(config *Config, configPath string, debug bool) ([]Rule, *Config, error) {
	if config == nil {
		return nil, nil, fmt.Errorf("config cannot be nil")
	}

	// In tests, configPath might be a directory, but in real usage it's a file path
	// Let's use it as configDir if it's already a directory, or get its Dir
	configDir := configPath
	if fileInfo, err := os.Stat(configPath); err == nil && !fileInfo.IsDir() {
		configDir = filepath.Dir(configPath)
	} else if err != nil {
		// If it doesn't exist, assume it was a file path
		configDir = filepath.Dir(configPath)
	}

	includedRules, err := loadIncludedRules(config.Encryption.IncludeRules, configDir, debug, "additional rules")
	if err != nil {
		return nil, nil, err
	}

	return includedRules, config, nil
}
