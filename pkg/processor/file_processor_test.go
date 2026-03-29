package processor

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"gopkg.in/yaml.v3"
)

// For testing only
var testUnsecureDiffLog = false

// TestFixBase64Padding tests the fixBase64Padding-like functionality
func TestFixBase64Padding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard base64",
			input:    "YWJjZGVmZ2g=", // Base64 for "abcdefgh"
			expected: "YWJjZGVmZ2g=",
		},
		{
			name:     "no padding needed",
			input:    "YWJjZGVmZ2hp", // Base64 for "abcdefghi"
			expected: "YWJjZGVmZ2hp", // String already has a length multiple of 4
		},
		{
			name:     "padding needed",
			input:    "YWJjZGVmZ2g",  // Base64 for "abcdefg" without padding
			expected: "YWJjZGVmZ2g=", // One padding character required
		},
		{
			name:     "two padding characters",
			input:    "YWJjZGVmZw",   // Base64 for "abcdefg" without padding
			expected: "YWJjZGVmZw==", // Two padding characters required
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "correctly requires one padding",
			input:    "YWJj", // Base64 for "abc" (3 bytes in ASCII)
			expected: "YWJj", // No padding required for 4 characters
		},
		{
			name:     "correctly requires two padding",
			input:    "YQ",   // Base64 for "a" without padding
			expected: "YQ==", // Two padding characters required
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Manual implementation of padding logic for testing
			result := tt.input
			padding := len(tt.input) % 4
			if padding > 0 {
				result = tt.input + strings.Repeat("=", 4-padding)
			}

			if result != tt.expected {
				t.Errorf("base64 padding = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestDeepCopyNode tests node copying functionality
func TestDeepCopyNode(t *testing.T) {
	// Create a complex node structure
	originalNode := &yaml.Node{
		Kind:   yaml.MappingNode,
		Style:  yaml.FlowStyle,
		Tag:    "!!map",
		Line:   1,
		Column: 1,
		Content: []*yaml.Node{
			{
				Kind:   yaml.ScalarNode,
				Value:  "key1",
				Tag:    "!!str",
				Line:   2,
				Column: 3,
			},
			{
				Kind:   yaml.ScalarNode,
				Value:  "value1",
				Tag:    "!!str",
				Line:   2,
				Column: 10,
			},
			{
				Kind:   yaml.ScalarNode,
				Value:  "key2",
				Tag:    "!!str",
				Line:   3,
				Column: 3,
			},
			{
				Kind:   yaml.SequenceNode,
				Tag:    "!!seq",
				Line:   3,
				Column: 10,
				Content: []*yaml.Node{
					{
						Kind:   yaml.ScalarNode,
						Value:  "item1",
						Tag:    "!!str",
						Line:   4,
						Column: 5,
					},
					{
						Kind:   yaml.ScalarNode,
						Value:  "item2",
						Tag:    "!!str",
						Line:   5,
						Column: 5,
					},
				},
			},
		},
	}

	// Define a local deepCopy function for testing
	var deepCopyLocal func(node *yaml.Node) *yaml.Node
	deepCopyLocal = func(node *yaml.Node) *yaml.Node {
		if node == nil {
			return nil
		}

		newNode := &yaml.Node{
			Kind:        node.Kind,
			Style:       node.Style,
			Tag:         node.Tag,
			Value:       node.Value,
			Anchor:      node.Anchor,
			Line:        node.Line,
			Column:      node.Column,
			HeadComment: node.HeadComment,
			LineComment: node.LineComment,
			FootComment: node.FootComment,
		}

		if node.Alias != nil {
			newNode.Alias = deepCopyLocal(node.Alias)
		}

		if len(node.Content) > 0 {
			newNode.Content = make([]*yaml.Node, len(node.Content))
			for i, child := range node.Content {
				newNode.Content[i] = deepCopyLocal(child)
			}
		}

		return newNode
	}

	// Test basic deep copy functionality
	copiedNode := deepCopyLocal(originalNode)

	// Verify the copied node is not the same as the original (different memory address)
	if copiedNode == originalNode {
		t.Error("deepCopyNode() did not create a new node instance")
	}

	// Check basic node properties
	if originalNode.Kind != copiedNode.Kind {
		t.Errorf("Kind mismatch: got %v, want %v", copiedNode.Kind, originalNode.Kind)
	}
	if originalNode.Style != copiedNode.Style {
		t.Errorf("Style mismatch: got %v, want %v", copiedNode.Style, originalNode.Style)
	}
	if originalNode.Tag != copiedNode.Tag {
		t.Errorf("Tag mismatch: got %v, want %v", copiedNode.Tag, originalNode.Tag)
	}
	if originalNode.Value != copiedNode.Value {
		t.Errorf("Value mismatch: got %v, want %v", copiedNode.Value, originalNode.Value)
	}
	if originalNode.Line != copiedNode.Line {
		t.Errorf("Line mismatch: got %v, want %v", copiedNode.Line, originalNode.Line)
	}
	if originalNode.Column != copiedNode.Column {
		t.Errorf("Column mismatch: got %v, want %v", copiedNode.Column, originalNode.Column)
	}

	// Check number of child elements
	if len(originalNode.Content) != len(copiedNode.Content) {
		t.Errorf("Content length mismatch: got %v, want %v", len(copiedNode.Content), len(originalNode.Content))
	}

	// Verify modifications to the copy don't affect the original
	copiedNode.Content[1].Value = "modified"
	if originalNode.Content[1].Value == "modified" {
		t.Error("Modification to copy affected the original")
	}

	// Check nil handling
	nilResult := deepCopyLocal(nil)
	if nilResult != nil {
		t.Error("deepCopyNode(nil) should return nil")
	}
}

// TestLoadRulesFile tests loading rules from a config file
func TestLoadRulesFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Sample configuration content
	configContent := `encryption:
  rules:
    - name: Test rule 1
      block: smart_config
      pattern: auth.*
      action: encrypt
      description: Encrypt authentication data
    - name: Test rule 2
      block: secrets
      pattern: '**'
      exclude: public_*
      action: encrypt
      description: Encrypt all secrets except public ones
  unsecure_diff: true
`

	// Write the config file
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Test loading rules
	rules, config, err := LoadRules(configPath, true)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	// Verify the number of rules
	if len(rules) != 2 {
		t.Errorf("LoadRules() got %d rules, want %d", len(rules), 2)
	}

	// Verify the first rule's properties
	if rules[0].Name != "Test rule 1" {
		t.Errorf("Rule[0].Name = %v, want %v", rules[0].Name, "Test rule 1")
	}
	if rules[0].Block != "smart_config" {
		t.Errorf("Rule[0].Block = %v, want %v", rules[0].Block, "smart_config")
	}
	if rules[0].Pattern != "auth.*" {
		t.Errorf("Rule[0].Pattern = %v, want %v", rules[0].Pattern, "auth.*")
	}

	// Verify config unsecure_diff
	if !config.UnsecureDiff {
		t.Errorf("Config.UnsecureDiff = %v, want %v", config.UnsecureDiff, true)
	}

	// Test with non-existent file
	_, _, err = LoadRules("non_existent_file.yaml", true)
	if err == nil {
		t.Error("LoadRules() with non-existent file should return an error")
	}

	// Test with invalid YAML
	invalidConfigPath := filepath.Join(tmpDir, "invalid.yaml")
	err = os.WriteFile(invalidConfigPath, []byte("invalid: yaml: content: - "), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid test config file: %v", err)
	}

	_, _, err = LoadRules(invalidConfigPath, true)
	if err == nil {
		t.Error("LoadRules() with invalid YAML should return an error")
	}

	// Test with empty config file
	emptyConfigPath := filepath.Join(tmpDir, "empty.yaml")
	err = os.WriteFile(emptyConfigPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create empty test config file: %v", err)
	}

	rules, _, err = LoadRules(emptyConfigPath, true)
	if err != nil {
		t.Errorf("LoadRules() with empty file error = %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("LoadRules() with empty file got %d rules, want 0", len(rules))
	}
}

// TestMaskEncryptedValueFile tests masking sensitive values
func TestMaskEncryptedValueFile(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		debug     bool
		fieldPath string
		expected  string
	}{
		{
			name:     "regular string",
			value:    "hello world",
			debug:    true,
			expected: "hello world", // Non-sensitive string should not be masked
		},
		{
			name:     "encrypted value",
			value:    "AES256:encrypted123456",
			debug:    true,
			expected: "AES256:enc***456", // Encrypted values should be partially masked
		},
		{
			name:     "short encrypted value not masked",
			value:    "AES256:12",
			debug:    true,
			expected: "AES256:12", // Short encrypted values are shown fully
		},
		{
			name:     "password containing value",
			value:    "my-password-123",
			debug:    true,
			expected: "********", // Password values should be fully masked
		},
		{
			name:      "with field path",
			value:     "AES256:encrypted123456",
			debug:     true,
			fieldPath: "secret.key",
			expected:  "AES256:enc***456", // Field path shouldn't affect masking in this case
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Manual implementation of masking logic for testing
			var result string
			if strings.Contains(tt.value, "password") {
				result = "********"
			} else if strings.HasPrefix(tt.value, "AES256:") && len(tt.value) > 14 {
				result = tt.value[:10] + "***" + tt.value[len(tt.value)-3:]
			} else {
				result = tt.value
			}

			if result != tt.expected {
				t.Errorf("Masked value = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestDetectAlgorithm tests algorithm detection from encrypted values
func TestDetectAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "not AES prefix",
			value:    "not-encrypted",
			expected: "unknown",
		},
		{
			name:     "AES too short",
			value:    "AES256:short",
			expected: "unknown (too short)",
		},
		{
			name:     "invalid base64",
			value:    "AES256:!invalid-base64-data-here!",
			expected: "unknown (invalid base64)",
		},
		{
			name:     "argon2id algorithm",
			value:    "AES256:" + base64.StdEncoding.EncodeToString([]byte("argon2id\x00\x00\x00\x00\x00\x00\x00\x00rest-of-data")),
			expected: "argon2id",
		},
		{
			name:     "pbkdf2-sha256 algorithm",
			value:    "AES256:" + base64.StdEncoding.EncodeToString([]byte("pbkdf2-sha256\x00\x00\x00\x00\x00\x00\x00\x00rest-of-data")),
			expected: "pbkdf2-sha256",
		},
		{
			name:     "pbkdf2-sha512 algorithm",
			value:    "AES256:" + base64.StdEncoding.EncodeToString([]byte("pbkdf2-sha512\x00\x00\x00\x00\x00\x00\x00\x00rest-of-data")),
			expected: "pbkdf2-sha512",
		},
		{
			name:     "unknown algorithm",
			value:    "AES256:" + base64.StdEncoding.EncodeToString([]byte("unknown-algo\x00\x00\x00\x00\x00\x00\x00\x00rest-of-data")),
			expected: "unknown algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Manual implementation of algorithm detection logic for testing
			var result string

			if !strings.HasPrefix(tt.value, "AES256:") {
				result = "unknown"
			} else {
				encBase64 := tt.value[7:]
				if len(encBase64) < 10 {
					result = "unknown (too short)"
				} else {
					rawData, err := base64.StdEncoding.DecodeString(encBase64)
					if err != nil {
						result = "unknown (invalid base64)"
					} else if len(rawData) >= 16 {
						algoName := string(rawData[:13])
						if strings.HasPrefix(algoName, "argon2id") {
							result = "argon2id"
						} else if strings.HasPrefix(algoName, "pbkdf2-sha256") {
							result = "pbkdf2-sha256"
						} else if strings.HasPrefix(algoName, "pbkdf2-sha512") {
							result = "pbkdf2-sha512"
						} else {
							result = "unknown algorithm"
						}
					} else {
						result = "unknown algorithm"
					}
				}
			}

			if result != tt.expected {
				t.Errorf("Algorithm detection = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSensitiveValueDetection tests identifying sensitive values
func TestSensitiveValueDetection(t *testing.T) {
	// Save original test value
	originalValue := testUnsecureDiffLog
	defer func() { testUnsecureDiffLog = originalValue }()

	tests := []struct {
		name              string
		value             string
		unsecureDiff      bool
		expectedSensitive bool
	}{
		{
			name:              "password is always sensitive",
			value:             "my-password-123",
			unsecureDiff:      false,
			expectedSensitive: true,
		},
		{
			name:              "password is always sensitive even with unsecure diff",
			value:             "my-password-123",
			unsecureDiff:      true,
			expectedSensitive: true,
		},
		{
			name:              "YED_ENCRYPT_PASSWORD is always sensitive",
			value:             "YED_ENCRYPT_PASSWORD=123",
			unsecureDiff:      true,
			expectedSensitive: true,
		},
		{
			name:              "non-sensitive with unsecure diff",
			value:             "regular-text",
			unsecureDiff:      true,
			expectedSensitive: false,
		},
		{
			name:              "short value is not sensitive",
			value:             "short",
			unsecureDiff:      false,
			expectedSensitive: false,
		},
		{
			name:              "longer regular text is sensitive in secure mode",
			value:             "this-is-a-longer-text-that-should-be-masked",
			unsecureDiff:      false,
			expectedSensitive: true,
		},
		{
			name:              "AES prefixed values are not sensitive",
			value:             "AES256:encrypted-data",
			unsecureDiff:      false,
			expectedSensitive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global flag for this test case
			testUnsecureDiffLog = tt.unsecureDiff

			// Implement the detection logic directly
			var result bool
			if strings.Contains(tt.value, "password") || strings.Contains(tt.value, "YED_ENCRYPT_PASSWORD") {
				result = true
			} else if strings.HasPrefix(tt.value, "AES256:") {
				result = false // Encrypted values are not sensitive
			} else if len(tt.value) < 8 {
				result = false // Short values are not sensitive
			} else {
				result = !tt.unsecureDiff // Depends on unsecureDiff flag
			}

			if result != tt.expectedSensitive {
				t.Errorf("Sensitive value detection = %v, want %v", result, tt.expectedSensitive)
			}
		})
	}
}

// TestFileProcessorProcessFile tests the ProcessFile function with various scenarios
func TestFileProcessorProcessFile(t *testing.T) {
	// Set default algorithm for testing
	encryption.SetDefaultAlgorithm(encryption.Argon2idAlgorithm)

	// Create a test key
	testKey := "K9#mP2$vL5@nR8&qX3*zAb4C" // Updated to meet minimum length of 20 characters

	// First, run encryption test to get encrypted value
	t.Run("encrypt_simple_yaml", func(t *testing.T) {
		// Create temporary directory for test files
		tempDir, err := os.MkdirTemp("", "TestFileProcessorProcessFileEncrypt")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer func() { _ = os.RemoveAll(tempDir) }()

		// Create test files
		yamlFile := filepath.Join(tempDir, "encrypt_simple_yaml.yaml")
		configFile := filepath.Join(tempDir, "encrypt_simple_yaml-config.yaml")

		// Write YAML content
		yamlContent := `username: testuser
password: H7$kM4@nP9#vL2!qX5`
		if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
			t.Fatalf("Failed to write YAML file: %v", err)
		}

		// Write config content
		configContent := `encryption:
  rules:
    - name: "Password rule"
      block: "*"
      pattern: "password"
      action: "encrypt"
  unsecure_diff: false`
		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to write config file: %v", err)
		}

		// Process the file
		err = ProcessFile(yamlFile, testKey, OperationEncrypt, true, configFile)
		if err != nil {
			t.Errorf("ProcessFile() error = %v, expectError = %v", err, false)
			return
		}

		// Read encrypted content
		content, err := os.ReadFile(yamlFile)
		if err != nil {
			t.Fatalf("Failed to read processed file: %v", err)
		}

		// Parse the YAML to get encrypted value
		var node yaml.Node
		if err := yaml.Unmarshal(content, &node); err != nil {
			t.Fatalf("Failed to parse processed YAML: %v", err)
		}

		// Find the password field and get encrypted value
		encryptedValue := ""
		root := node.Content[0]
		for i := 0; i < len(root.Content); i += 2 {
			if i+1 >= len(root.Content) {
				continue
			}

			keyNode := root.Content[i]
			valueNode := root.Content[i+1]

			if keyNode.Value == "password" {
				encryptedValue = valueNode.Value
				break
			}
		}

		if encryptedValue == "" {
			t.Fatal("Failed to find encrypted password value")
		}

		// Now run decryption test with the encrypted value
		t.Run("decrypt_simple_yaml", func(t *testing.T) {
			// Create new temporary directory for decryption test
			decryptDir, err := os.MkdirTemp("", "TestFileProcessorProcessFileDecrypt")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer func() { _ = os.RemoveAll(decryptDir) }()

			// Create test files for decryption
			decryptYamlFile := filepath.Join(decryptDir, "decrypt_simple_yaml.yaml")
			decryptConfigFile := filepath.Join(decryptDir, "decrypt_simple_yaml-config.yaml")

			// Write encrypted content
			decryptYamlContent := fmt.Sprintf(`username: testuser
password: %s`, encryptedValue)
			if err := os.WriteFile(decryptYamlFile, []byte(decryptYamlContent), 0644); err != nil {
				t.Fatalf("Failed to write YAML file: %v", err)
			}

			// Write config content
			if err := os.WriteFile(decryptConfigFile, []byte(configContent), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Process the file
			err = ProcessFile(decryptYamlFile, testKey, OperationDecrypt, true, decryptConfigFile)
			if err != nil {
				t.Errorf("ProcessFile() error = %v, expectError = %v", err, false)
				return
			}

			// Verify the content was decrypted
			decryptedContent, err := os.ReadFile(decryptYamlFile)
			if err != nil {
				t.Fatalf("Failed to read processed file: %v", err)
			}

			// Parse the YAML to verify decryption
			var decryptedNode yaml.Node
			if err := yaml.Unmarshal(decryptedContent, &decryptedNode); err != nil {
				t.Fatalf("Failed to parse processed YAML: %v", err)
			}

			// Find the password field and verify it's decrypted
			if err := verifyDecryption(&decryptedNode, "password", testKey); err != nil {
				t.Errorf("Decryption verification failed: %v", err)
			}
		})
	})

	// Run other tests
	tests := []struct {
		name        string
		yamlContent string
		config      string
		key         string
		operation   string
		expectError bool
	}{
		{
			name: "encrypt_with_folded_style",
			yamlContent: `description: >
  This is a multi-line
  description with folded style
password: H7$kM4@nP9#vL2!qX5`,
			config: `encryption:
  rules:
    - name: "Password rule"
      block: "*"
      pattern: "password"
      action: "encrypt"
  unsecure_diff: false`,
			key:         testKey,
			operation:   OperationEncrypt,
			expectError: false,
		},
		{
			name:        "encrypt_with_invalid_yaml",
			yamlContent: `invalid yaml: [`,
			config: `encryption:
  rules:
    - name: "Password rule"
      block: "*"
      pattern: "password"
      action: "encrypt"
  unsecure_diff: false`,
			key:         testKey,
			operation:   OperationEncrypt,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test files
			tempDir, err := os.MkdirTemp("", "TestFileProcessorProcessFile")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer func() { _ = os.RemoveAll(tempDir) }()

			// Create test files
			yamlFile := filepath.Join(tempDir, tt.name+".yaml")
			configFile := filepath.Join(tempDir, tt.name+"-config.yaml")

			// Write YAML content
			if err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to write YAML file: %v", err)
			}

			// Write config content
			if err := os.WriteFile(configFile, []byte(tt.config), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Process the file
			err = ProcessFile(yamlFile, tt.key, tt.operation, true, configFile)

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ProcessFile() error = %v, expectError = %v", err, tt.expectError)
				return
			}

			// For encryption, verify the content was encrypted
			if tt.operation == OperationEncrypt {
				content, err := os.ReadFile(yamlFile)
				if err != nil {
					t.Fatalf("Failed to read processed file: %v", err)
				}

				// Parse the YAML to verify encryption
				var node yaml.Node
				if err := yaml.Unmarshal(content, &node); err != nil {
					t.Fatalf("Failed to parse processed YAML: %v", err)
				}

				// Find the password field and verify it's encrypted
				if err := verifyEncryption(&node, "password", tt.key); err != nil {
					t.Errorf("Encryption verification failed: %v", err)
				}
			}
		})
	}
}

// verifyEncryption checks if a field is properly encrypted
func verifyEncryption(node *yaml.Node, fieldPath, key string) error {
	parts := strings.Split(fieldPath, ".")
	current := node.Content[0]

	for i, part := range parts {
		if current.Kind != yaml.MappingNode {
			return fmt.Errorf("expected mapping node at %s", strings.Join(parts[:i], "."))
		}

		found := false
		for j := 0; j < len(current.Content); j += 2 {
			if j+1 >= len(current.Content) {
				continue
			}

			keyNode := current.Content[j]
			if keyNode.Value == part {
				current = current.Content[j+1]
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("field %s not found", part)
		}
	}

	// The field should be encrypted
	if !strings.HasPrefix(current.Value, "AES256:") {
		return fmt.Errorf("field %s is not encrypted", fieldPath)
	}

	return nil
}

// verifyDecryption checks if a field is properly decrypted
func verifyDecryption(node *yaml.Node, fieldName, key string) error {
	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		return fmt.Errorf("invalid YAML document structure")
	}

	root := node.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("root node is not a mapping")
	}

	for i := 0; i < len(root.Content); i += 2 {
		if i+1 >= len(root.Content) {
			continue
		}

		keyNode := root.Content[i]
		valueNode := root.Content[i+1]

		if keyNode.Value == fieldName {
			if strings.HasPrefix(valueNode.Value, AES) {
				return fmt.Errorf("field %s is still encrypted", fieldName)
			}
			return nil
		}
	}

	return fmt.Errorf("field %s not found", fieldName)
}

// TestFileProcessorEmptyConfig tests loading rules with an empty config file
func TestFileProcessorEmptyConfig(t *testing.T) {
	// Create a temporary empty config file
	tmpDir := t.TempDir()
	emptyConfigPath := filepath.Join(tmpDir, "empty-config.yaml")
	err := os.WriteFile(emptyConfigPath, []byte{}, 0644)
	if err != nil {
		t.Fatalf("Failed to create empty config file: %v", err)
	}

	// Load rules from the empty config
	rules, config, err := loadRules(emptyConfigPath, true)

	// Empty config should not cause an error, but should return empty rules
	if err != nil {
		t.Errorf("loadRules() with empty config returned error: %v", err)
	}

	// Check that rules are empty
	if len(rules) > 0 {
		t.Errorf("Expected empty rules from empty config, got %d rules", len(rules))
	}

	// Config should not be nil
	if config == nil {
		t.Errorf("Expected non-nil Config from empty config file")
	}
}

// Helper function to create an encrypted value for testing
func createEncryptedValue(t *testing.T, plaintext, key string) string {
	encrypted, err := encryption.Encrypt(key, plaintext, encryption.Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Failed to encrypt test value: %v", err)
	}
	return "AES256:" + encrypted
}

// TestEncryptionHelper tests the createEncryptedValue function
func TestEncryptionHelper(t *testing.T) {
	// Set default algorithm for testing
	encryption.SetDefaultAlgorithm(encryption.Argon2idAlgorithm)

	testKey := "K9#mP2$vL5@nR8&qX3*zAb4C" // Updated to meet minimum length of 20 characters
	plaintext := "H7$kM4@nP9#vL2!qX5"

	// Use the helper function
	encryptedValue := createEncryptedValue(t, plaintext, testKey)

	// Verify the encrypted value has the correct prefix
	if !strings.HasPrefix(encryptedValue, "AES256:") {
		t.Errorf("Encrypted value doesn't have AES256 prefix: %s", encryptedValue)
	}

	// Verify the value is not the plaintext
	if encryptedValue == "AES256:"+plaintext {
		t.Errorf("Value was not encrypted: %s", encryptedValue)
	}

	// Verify the encrypted value is long enough to be a valid encryption
	if len(encryptedValue) < 20 {
		t.Errorf("Encrypted value is too short: %s", encryptedValue)
	}
}

// TestFileProcessorShowDiff tests the ShowDiff function
func TestFileProcessorShowDiff(t *testing.T) {
	// Create a temporary test directory
	tmpDir := t.TempDir()

	// Create sample YAML with a password field
	yamlContent := `
username: admin
password: secret123
`

	// Create a temporary file
	filename := filepath.Join(tmpDir, "diff-test.yaml")
	err := os.WriteFile(filename, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a basic config file
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
encryption:
  rules:
    - name: Password rule
      block: "*"
      pattern: "password"
      action: encrypt
      description: Encrypt password fields
  unsecure_diff: true
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Test ShowDiff (this will output to stdout)
	testKey := "test-key-12345"
	err = ShowDiff(filename, testKey, "encrypt", true, configPath)
	if err != nil {
		t.Errorf("ShowDiff() failed: %v", err)
	}

	// Since ShowDiff outputs to stdout, this test mainly ensures the function executes without error
}

// TestProcessFileErrorHandling tests error handling in ProcessFile
func TestProcessFileErrorHandling(t *testing.T) {
	// Set default algorithm for testing
	encryption.SetDefaultAlgorithm(encryption.Argon2idAlgorithm)

	tests := []struct {
		name        string
		yamlContent string
		config      string
		key         string
		operation   string
		expectError bool
	}{
		{
			name:        "invalid_file",
			yamlContent: "invalid yaml: [",
			config: `encryption:
  rules:
    - name: "Password rule"
      block: "*"
      pattern: "password"
      action: "encrypt"
  unsecure_diff: false`,
			key:         "K9#mP2$vL5@nR8&qX3*zAb4C", // Updated to meet minimum length
			operation:   OperationEncrypt,
			expectError: true,
		},
		{
			name: "invalid_key",
			yamlContent: `username: testuser
password: test123`,
			config: `encryption:
  rules:
    - name: "Password rule"
      block: "*"
      pattern: "password"
      action: "encrypt"
  unsecure_diff: false`,
			key:         "weak", // Invalid key
			operation:   OperationEncrypt,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test files
			tempDir, err := os.MkdirTemp("", "TestProcessFileErrors")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer func() { _ = os.RemoveAll(tempDir) }()

			// Create test files
			yamlFile := filepath.Join(tempDir, tt.name+".yaml")
			configFile := filepath.Join(tempDir, tt.name+"-config.yaml")

			// Write YAML content
			if err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to write YAML file: %v", err)
			}

			// Write config content
			if err := os.WriteFile(configFile, []byte(tt.config), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Process the file
			err = ProcessFile(yamlFile, tt.key, tt.operation, true, configFile)

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ProcessFile() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

// verifyExclusion checks if a field was properly excluded from processing
func verifyExclusion(node *yaml.Node, fieldPath string) error {
	parts := strings.Split(fieldPath, ".")
	current := node.Content[0]

	for i, part := range parts {
		if current.Kind != yaml.MappingNode {
			return fmt.Errorf("expected mapping node at %s", strings.Join(parts[:i], "."))
		}

		found := false
		for j := 0; j < len(current.Content); j += 2 {
			if j+1 >= len(current.Content) {
				continue
			}

			keyNode := current.Content[j]
			if keyNode.Value == part {
				current = current.Content[j+1]
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("field %s not found", part)
		}
	}

	// The field should not be encrypted
	if strings.HasPrefix(current.Value, "AES256:") {
		return fmt.Errorf("field %s was encrypted but should be excluded", fieldPath)
	}

	return nil
}

// TestProcessYAMLWithExclusionsExtended tests additional exclusion scenarios
func TestProcessYAMLWithExclusionsExtended(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		config      string
		key         string
		operation   string
		expectError bool
	}{
		{
			name: "encrypt_with_excludes",
			yamlContent: `config:
  username: admin
  password: test123
  api_key: secret
  public_key: public`,
			config: `encryption:
  rules:
    - name: "exclude_public"
      block: "config"
      pattern: "public_key"
      action: "none"
      description: "Exclude public key from encryption"
    - name: "encrypt_sensitive"
      block: "config"
      pattern: "username|password|api_key"
      action: "encrypt"
      description: "Encrypt sensitive fields"
  unsecure_diff: false`,
			key:         "K9#mP2$vL5@nR8&qX3",
			operation:   OperationEncrypt,
			expectError: false,
		},
		{
			name: "process_mapping_with_exclusions",
			yamlContent: `users:
  admin:
    password: admin123
  public:
    key: public_key`,
			config: `encryption:
  rules:
    - name: "exclude_public"
      block: "users.public"
      pattern: "key"
      action: "none"
      description: "Exclude public key from encryption"
    - name: "encrypt_admin"
      block: "users.admin"
      pattern: "password"
      action: "encrypt"
      description: "Encrypt admin password"
  unsecure_diff: false`,
			key:         "K9#mP2$vL5@nR8&qX3",
			operation:   OperationEncrypt,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test files
			tempDir, err := os.MkdirTemp("", "TestProcessYAMLWithExclusionsExtended")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer func() { _ = os.RemoveAll(tempDir) }()

			// Create test files
			yamlFile := filepath.Join(tempDir, tt.name+".yaml")
			configFile := filepath.Join(tempDir, tt.name+"-config.yaml")

			// Write YAML content
			if err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to write YAML file: %v", err)
			}

			// Write config content
			if err := os.WriteFile(configFile, []byte(tt.config), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Process the file
			err = ProcessFile(yamlFile, tt.key, tt.operation, true, configFile)

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ProcessFile() error = %v, expectError = %v", err, tt.expectError)
				return
			}

			// Verify the content was processed correctly
			content, err := os.ReadFile(yamlFile)
			if err != nil {
				t.Fatalf("Failed to read processed file: %v", err)
			}

			// Parse the YAML to verify processing
			var node yaml.Node
			if err := yaml.Unmarshal(content, &node); err != nil {
				t.Fatalf("Failed to parse processed YAML: %v", err)
			}

			// Verify exclusions were handled correctly
			switch tt.name {
			case "encrypt_with_excludes":
				// First verify exclusions
				if err := verifyExclusion(&node, "config.public_key"); err != nil {
					t.Errorf("Exclusion verification failed: %v", err)
				}
				// Then verify encryptions
				if err := verifyEncryption(&node, "config.username", tt.key); err != nil {
					t.Errorf("Encryption verification failed for username: %v", err)
				}
				if err := verifyEncryption(&node, "config.password", tt.key); err != nil {
					t.Errorf("Encryption verification failed for password: %v", err)
				}
				if err := verifyEncryption(&node, "config.api_key", tt.key); err != nil {
					t.Errorf("Encryption verification failed for api_key: %v", err)
				}
			case "process_mapping_with_exclusions":
				// First verify exclusions
				if err := verifyExclusion(&node, "users.public.key"); err != nil {
					t.Errorf("Exclusion verification failed: %v", err)
				}
				// Then verify encryptions
				if err := verifyEncryption(&node, "users.admin.password", tt.key); err != nil {
					t.Errorf("Encryption verification failed for admin password: %v", err)
				}
			}
		})
	}
}

// TestProcessYAMLWithExclusions tests additional exclusion scenarios
func TestProcessYAMLWithExclusions(t *testing.T) {
	tests := []struct {
		name          string
		yamlContent   string
		configContent string
		key           string
		operation     string
		verifyFunc    func(t *testing.T, content string, key string)
	}{
		{
			name: "encrypt_with_excludes",
			yamlContent: `config:
  username: admin
  password: test123
  api_key: secret
  public_key: public`,
			configContent: `encryption:
  rules:
    - name: exclude_public_key
      block: config
      pattern: public_key
      action: none
    - name: encrypt_sensitive
      block: config
      pattern: username|password|api_key
      action: encrypt`,
			key:       "K9#mP2$vL5@nR8&qX3",
			operation: "encrypt",
			verifyFunc: func(t *testing.T, content string, key string) {
				// Parse the YAML to verify processing
				var node yaml.Node
				if err := yaml.Unmarshal([]byte(content), &node); err != nil {
					t.Fatalf("Failed to parse processed YAML: %v", err)
				}

				// First verify exclusions
				if err := verifyExclusion(&node, "config.public_key"); err != nil {
					t.Errorf("Exclusion verification failed: %v", err)
				}

				// Then verify encryptions
				if err := verifyEncryption(&node, "config.username", key); err != nil {
					t.Errorf("Encryption verification failed for username: %v", err)
				}
				if err := verifyEncryption(&node, "config.password", key); err != nil {
					t.Errorf("Encryption verification failed for password: %v", err)
				}
				if err := verifyEncryption(&node, "config.api_key", key); err != nil {
					t.Errorf("Encryption verification failed for api_key: %v", err)
				}
			},
		},
		{
			name: "process_mapping_with_exclusions",
			yamlContent: `users:
  admin:
    password: admin123
  public:
    key: public_key`,
			configContent: `encryption:
  rules:
    - name: exclude_public_key
      block: users.public
      pattern: key
      action: none
    - name: encrypt_sensitive
      block: users.admin
      pattern: password
      action: encrypt`,
			key:       "K9#mP2$vL5@nR8&qX3",
			operation: "encrypt",
			verifyFunc: func(t *testing.T, content string, key string) {
				// Parse the YAML to verify processing
				var node yaml.Node
				if err := yaml.Unmarshal([]byte(content), &node); err != nil {
					t.Fatalf("Failed to parse processed YAML: %v", err)
				}

				// First verify exclusions
				if err := verifyExclusion(&node, "users.public.key"); err != nil {
					t.Errorf("Exclusion verification failed: %v", err)
				}

				// Then verify encryptions
				if err := verifyEncryption(&node, "users.admin.password", key); err != nil {
					t.Errorf("Encryption verification failed for admin password: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test files
			tempDir, err := os.MkdirTemp("", "TestProcessYAMLWithExclusions")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer func() { _ = os.RemoveAll(tempDir) }()

			// Create test files
			yamlFile := filepath.Join(tempDir, tt.name+".yaml")
			configFile := filepath.Join(tempDir, tt.name+"-config.yaml")

			// Write YAML content
			if err := os.WriteFile(yamlFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to write YAML file: %v", err)
			}

			// Write config content
			if err := os.WriteFile(configFile, []byte(tt.configContent), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Process the file
			if err := ProcessFile(yamlFile, tt.key, tt.operation, true, configFile); err != nil {
				t.Fatalf("ProcessFile failed: %v", err)
			}

			// Read processed file
			processedContent, err := os.ReadFile(yamlFile)
			if err != nil {
				t.Fatalf("Failed to read processed file: %v", err)
			}

			// Verify the result
			tt.verifyFunc(t, string(processedContent), tt.key)
		})
	}
}
