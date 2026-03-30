package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/awnumar/memguard"
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
}

// parseFlags parses command line arguments and returns an appFlags struct
func parseFlags() (appFlags, error) {
	// Define flags with short and long forms
	var flags appFlags

	// Required flags for main operation
	flag.StringVar(&flags.filename, "file", "", "Path to the YAML file")
	flag.StringVar(&flags.filename, "f", "", "")

	flag.StringVar(&flags.key, "key", "", "Encryption/decryption key")
	flag.StringVar(&flags.key, "k", "", "")

	flag.StringVar(&flags.operation, "operation", "", "Operation to perform (encrypt/decrypt)")
	flag.StringVar(&flags.operation, "o", "", "")

	// Operation control flags
	flag.BoolVar(&flags.dryRun, "dry-run", false, "Print the result without modifying the file")
	flag.BoolVar(&flags.dryRun, "d", false, "")

	flag.BoolVar(&flags.diff, "diff", false, "Show differences between original and encrypted values")
	flag.BoolVar(&flags.diff, "D", false, "")

	// Logging and information flags
	flag.BoolVar(&flags.debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&flags.debug, "v", false, "")

	flag.BoolVar(&flags.showVersion, "version", false, "Show version information")
	flag.BoolVar(&flags.showVersion, "V", false, "")

	// Advanced configuration flags
	flag.StringVar(&flags.algorithm, "algorithm", "", "Key derivation algorithm to use (argon2id, pbkdf2-sha256, pbkdf2-sha512)")
	flag.StringVar(&flags.algorithm, "a", "", "")

	flag.StringVar(&flags.configPath, "config", "", "Path to the .yed_config.yml file (default: .yed_config.yml in current directory)")
	flag.StringVar(&flags.configPath, "c", "", "")

	flag.BoolVar(&flags.validateRules, "validate", false, "Validate configuration and rules without performing encryption/decryption")
	flag.BoolVar(&flags.validateRules, "C", false, "")

	// Performance analysis flags
	flag.BoolVar(&flags.benchmark, "benchmark", false, "Run performance benchmarks")
	flag.BoolVar(&flags.benchmark, "b", false, "")

	flag.StringVar(&flags.benchFile, "bench-file", "", "Path to save benchmark results (default: stdout)")
	flag.StringVar(&flags.benchFile, "B", "", "")

	// Additional rule files
	flag.StringVar(&flags.includeRules, "include-rules", "", "Comma-separated list of additional rule files to include")
	flag.StringVar(&flags.includeRules, "i", "", "")

	// Override default usage
	flag.Usage = func() {
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

		fmt.Fprintln(os.Stderr, "For more information, visit: https://github.com/atlet99/yaml-encrypter-decrypter")
	}

	flag.Parse()

	return flags, nil
}

// getEncryptionKey returns the encryption key from flag or environment variable
func getEncryptionKey(flagKey string, debug bool) (string, error) {
	// Create secure buffer for key
	keyBuf := memguard.NewBuffer(0)
	defer keyBuf.Destroy()

	var key string

	if flagKey != "" {
		// Copy key to secure buffer
		keyBuf = memguard.NewBufferFromBytes([]byte(flagKey))
		if keyBuf == nil {
			return "", fmt.Errorf("failed to create secure buffer for key")
		}
		key = string(keyBuf.Bytes())
	} else {
		envKey := os.Getenv("YED_ENCRYPTION_KEY")
		if envKey != "" {
			if debug {
				fmt.Println("[DEBUG] Using encryption key from YED_ENCRYPTION_KEY environment variable")
			}
			// Copy key from environment variable to secure buffer
			keyBuf = memguard.NewBufferFromBytes([]byte(envKey))
			if keyBuf == nil {
				return "", fmt.Errorf("failed to create secure buffer for key")
			}
			key = string(keyBuf.Bytes())
		}
	}

	if key == "" {
		return "", fmt.Errorf("error: encryption key not provided")
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
