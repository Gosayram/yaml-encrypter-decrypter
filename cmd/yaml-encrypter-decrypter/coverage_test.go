package main

import (
	"flag"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestMainWithExitCode_Coverage(t *testing.T) {
	// Save original Args and restore them later
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tempDir := t.TempDir()
	yamlFile := filepath.Join(tempDir, "test.yml")
	err := os.WriteFile(yamlFile, []byte("key: value"), 0644)
	assert.NoError(t, err)

	configFile := filepath.Join(tempDir, ".yed_config.yml")
	err = os.WriteFile(configFile, []byte("encryption:\n  rules:\n    - name: r1\n      block: '*'\n      pattern: key\n      action: encrypt"), 0644)
	assert.NoError(t, err)

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"version", []string{"cmd", "-version"}, 0},
		{"no args", []string{"cmd"}, 1},
		{"validate", []string{"cmd", "-validate", "-config", configFile}, 0},
		{"invalid operation", []string{"cmd", "-file", yamlFile, "-key", "HighlySecureAndUniquePass-2024!", "-operation", "invalid"}, 1},
		{"dry-run", []string{"cmd", "-file", yamlFile, "-key", "HighlySecureAndUniquePass-2024!", "-operation", "encrypt", "-dry-run", "-config", configFile}, 0},
		{"diff", []string{"cmd", "-file", yamlFile, "-key", "HighlySecureAndUniquePass-2024!", "-operation", "encrypt", "-diff", "-config", configFile}, 0},
		{"benchmark", []string{"cmd", "-benchmark"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			// Reset flag.CommandLine to allow re-parsing
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

			got := mainWithExitCode()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetEncryptionKey_Coverage(t *testing.T) {
	t.Run("from flag", func(t *testing.T) {
		key, err := getEncryptionKey("HighlySecureAndUniquePass-2024!", false)
		assert.NoError(t, err)
		assert.Equal(t, "HighlySecureAndUniquePass-2024!", key)
	})

	t.Run("from env", func(t *testing.T) {
		err := os.Setenv("YED_ENCRYPTION_KEY", "HighlySecureAndUniquePass-2024!")
		assert.NoError(t, err)
		defer func() {
			err := os.Unsetenv("YED_ENCRYPTION_KEY")
			assert.NoError(t, err)
		}()
		key, err := getEncryptionKey("", false)
		assert.NoError(t, err)
		assert.Equal(t, "HighlySecureAndUniquePass-2024!", key)
	})

	t.Run("empty", func(t *testing.T) {
		_, err := getEncryptionKey("", false)
		assert.Error(t, err)
	})

	t.Run("too short", func(t *testing.T) {
		_, err := getEncryptionKey("short", false)
		assert.Error(t, err)
	})
}
