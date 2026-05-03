package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/spf13/pflag"
)

// CLI flags
type appFlags struct {
	filename      string
	key           string
	operation     string
	dryRun        bool
	diff          bool
	debug         bool
	showVersion   bool
	algorithm     string
	benchmark     bool
	benchFile     string
	configPath    string
	validateRules bool
	includeRules  string
	// Logging configuration
	logLevel  string
	logFormat string
	logOutput string
}

const (
	// NoOptDefValue is the default value for boolean flags without explicit values
	NoOptDefValue = "true"
)

var appFlagsInstance = appFlags{}

// initFlags initializes all command line flags
func initFlags() {
	// Required flags for main operation
	pflag.StringVarP(&appFlagsInstance.filename, "file", "f", "", "Path to the YAML file")
	pflag.StringVarP(&appFlagsInstance.key, "key", "k", "", "Encryption/decryption key")
	pflag.StringVarP(&appFlagsInstance.operation, "operation", "o", "", "Operation to perform (encrypt/decrypt)")

	// Operation control flags
	pflag.BoolVarP(&appFlagsInstance.dryRun, "dry-run", "d", false, "Print the result without modifying the file")
	pflag.BoolVarP(&appFlagsInstance.diff, "diff", "D", false, "Show differences between original and encrypted values")

	// Logging and information flags
	pflag.BoolVarP(&appFlagsInstance.debug, "debug", "v", false, "Enable debug logging")
	pflag.BoolVarP(&appFlagsInstance.showVersion, "version", "V", false, "Show version information")

	// Set NoOptDefVal for boolean flags to allow them to be set without values
	if flag := pflag.CommandLine.Lookup("debug"); flag != nil {
		flag.NoOptDefVal = NoOptDefValue
	}
	if flag := pflag.CommandLine.Lookup("version"); flag != nil {
		flag.NoOptDefVal = NoOptDefValue
	}
	if flag := pflag.CommandLine.Lookup("dry-run"); flag != nil {
		flag.NoOptDefVal = NoOptDefValue
	}
	if flag := pflag.CommandLine.Lookup("diff"); flag != nil {
		flag.NoOptDefVal = NoOptDefValue
	}
	if flag := pflag.CommandLine.Lookup("benchmark"); flag != nil {
		flag.NoOptDefVal = NoOptDefValue
	}
	if flag := pflag.CommandLine.Lookup("validate"); flag != nil {
		flag.NoOptDefVal = NoOptDefValue
	}

	// Advanced configuration flags
	pflag.StringVarP(&appFlagsInstance.algorithm, "algorithm", "a", "", "Key derivation algorithm to use (argon2id, pbkdf2-sha256, pbkdf2-sha512)")
	pflag.StringVarP(&appFlagsInstance.configPath, "config", "c", "", "Path to the .yed_config.yml file (default: .yed_config.yml in current directory)")
	pflag.BoolVarP(&appFlagsInstance.validateRules, "validate", "C", false, "Validate configuration and rules without performing encryption/decryption")

	// Performance analysis flags
	pflag.BoolVarP(&appFlagsInstance.benchmark, "benchmark", "b", false, "Run performance benchmarks")
	pflag.StringVarP(&appFlagsInstance.benchFile, "bench-file", "B", "", "Path to save benchmark results (default: stdout)")

	// Additional rule files
	pflag.StringVarP(&appFlagsInstance.includeRules, "include-rules", "i", "", "Comma-separated list of additional rule files to include")

	// Logging configuration flags
	pflag.StringVarP(&appFlagsInstance.logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")
	pflag.StringVarP(&appFlagsInstance.logFormat, "log-format", "F", "console", "Log format (console, json)")
	pflag.StringVarP(&appFlagsInstance.logOutput, "log-output", "O", "stderr", "Log output (stdout, stderr, or file path)")

	// Override default usage
	pflag.Usage = func() {
		fmt.Fprintln(os.Stderr, "A tool for encrypting and decrypting YAML files while preserving formatting.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  yaml-encrypter-decrypter [options] <file>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -operation, -o       <string>        Operation to perform (encrypt/decrypt)")
		fmt.Fprintln(os.Stderr, "  -key, -k             <string>        Encryption/decryption key")
		fmt.Fprintln(os.Stderr, "  -diff, -D                            Show differences between original and processed values")

		// Print flags in organized groups
		fmt.Fprintln(os.Stderr, "Required Options:")
		fmt.Fprintln(os.Stderr, "  -file, -f 		<string>	Path to the YAML file to process")
		fmt.Fprintln(os.Stderr, "  -key, -k		  <string>		Encryption/decryption key (min 15 chars)")
		fmt.Fprintln(os.Stderr, "  -operation, -o 	<string>	Operation to perform (encrypt/decrypt)")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "Operation Control:")
		fmt.Fprintln(os.Stderr, "  -dry-run, -d          		Preview changes without modifying the file")
		fmt.Fprintln(os.Stderr, "  -diff, -D             		Show differences between original and processed values")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "Logging and Information:")
		fmt.Fprintln(os.Stderr, "  -debug, -v            		Enable detailed debug logging")
		fmt.Fprintln(os.Stderr, "  -log-level, -l       		Log level (debug, info, warn, error)")
		fmt.Fprintln(os.Stderr, "  -log-format, -F      		Log format (console, json)")
		fmt.Fprintln(os.Stderr, "  -log-output, -O      		Log output (stdout, stderr, or file path)")
		fmt.Fprintln(os.Stderr, "  -version, -V          		Display version and build information")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "Advanced Configuration:")
		fmt.Fprintln(os.Stderr, "  -algorithm, -a 	<string> 	Key derivation algorithm:")
		fmt.Fprintln(os.Stderr, "                         		argon2id (default), pbkdf2-sha256, pbkdf2-sha512")
		fmt.Fprintln(os.Stderr, "  -config, -c 		<string>   	Path to config file (default: .yed_config.yml)")
		fmt.Fprintln(os.Stderr, "  -validate, -C          		Validate configuration and rules without performing any operation")
		fmt.Fprintln(os.Stderr, "  -include-rules, -i <string>   	Comma-separated list of additional rule files to include")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "Performance Analysis:")
		fmt.Fprintln(os.Stderr, "  -benchmark, -b         		Run encryption/decryption performance tests")
		fmt.Fprintln(os.Stderr, "  -bench-file, -B 	<string> 	Save benchmark results to file (default: stdout)")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "Environment Variables:")
		fmt.Fprintln(os.Stderr, "  YED_ENCRYPTION_KEY     		Alternative way to provide encryption key")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  Encrypt a file:     yed -f config.yml -k 'your-secure-key' -o encrypt")
		fmt.Fprintln(os.Stderr, "  Decrypt a file:     yed -f config.yml -k 'your-secure-key' -o decrypt")
		fmt.Fprintln(os.Stderr, "  Preview changes:    yed -f config.yml -k 'your-secure-key' -o encrypt -d")
		fmt.Fprintln(os.Stderr, "  Show differences:   yed -f config.yml -k 'your-secure-key' -o encrypt -D")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "For more information, visit: https://github.com/Gosayram/yaml-encrypter-decrypter")
	}
}

// getEncryptionKey returns the encryption key from flag or environment variable
func getEncryptionKey(flagKey string, debug bool) (string, error) {
	var key string

	if flagKey != "" {
		key = flagKey
	} else {
		// Check environment variable
		envKey := os.Getenv("YED_ENCRYPTION_KEY")
		if envKey != "" {
			key = envKey
		} else {
			return "", fmt.Errorf("error: encryption key not provided")
		}
	}

	// Check key length
	if len(key) < encryption.PasswordRecommendedLength {
		return "", fmt.Errorf("error: encryption key must be at least %d characters long for adequate security", encryption.PasswordRecommendedLength)
	}

	return key, nil
}

// displayVersion prints the version information in a formatted way
func displayVersion() {
	// Check if version contains build information
	if strings.Contains(Version, "(build ") {
		// Extract version part (before the build info)
		parts := strings.Split(Version, " (build ")
		if len(parts) == VersionParts {
			version := parts[0]
			buildNumber := strings.TrimSuffix(parts[1], ")")
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Build: %s\n", buildNumber)
		} else {
			fmt.Printf("Version: %s\n", Version)
		}
	} else {
		fmt.Printf("Version: %s\n", Version)
	}
}
