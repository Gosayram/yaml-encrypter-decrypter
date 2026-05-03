package main

import (
	"os"
	"testing"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/logger"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestGetEncryptionKey_Coverage(t *testing.T) {
	// Initialize test logger
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

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
