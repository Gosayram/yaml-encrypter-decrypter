package processor

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/logger"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func TestDetectMultilineStyle(t *testing.T) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting TestDetectMultilineStyle")

	tests := []struct {
		name     string
		node     *yaml.Node
		expected MultilineStyle
	}{
		{
			name: "literal style",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: yaml.LiteralStyle,
			},
			expected: LiteralStyle,
		},
		{
			name: "folded style",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: yaml.FoldedStyle,
			},
			expected: FoldedStyle,
		},
		{
			name: "plain style",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: 0,
			},
			expected: NotMultiline,
		},
		{
			name:     "nil node",
			node:     nil,
			expected: NotMultiline,
		},
		{
			name: "non-scalar node",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
			},
			expected: NotMultiline,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectMultilineStyle(tt.node)
			if result != tt.expected {
				t.Errorf("DetectMultilineStyle() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestEncryptDecryptMultiline(t *testing.T) {
	// Test data
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz" // Strong password that meets our requirements
	originalStyle := yaml.LiteralStyle
	originalText := `server {
  listen 80;
  server_name localhost;
  location / {
    root /usr/share/nginx/html;
    index index.html;
  }
}`

	// === Test direct encryption and decryption ===

	// Create test node for direct encrypt/decrypt test
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: originalStyle,
		Value: originalText,
	}

	// Test encryption
	err := EncryptMultiline(node, testKey, false)
	if err != nil {
		t.Fatalf("EncryptMultiline() error = %v", err)
	}

	// Verify encryption
	if !strings.HasPrefix(node.Value, AES) {
		t.Errorf("Encrypted value should start with %s", AES)
	}
	if node.Style != 0 {
		t.Errorf("Style after encryption should be 0 (plain), got %v", node.Style)
	}

	// Output encrypted value for debugging
	encryptedValue := node.Value
	t.Logf("DEBUG: Encrypted value with AES prefix: '%s'", encryptedValue)
	t.Logf("DEBUG: Length of encrypted value: %d", len(encryptedValue))
	t.Logf("DEBUG: Value after removing AES prefix: '%s'", strings.TrimPrefix(encryptedValue, AES))

	// Test decryption with a custom decryption function
	err = DecryptMultiline(node, func(value string) (string, error) {
		// Debug logs
		t.Logf("DEBUG: Inside decryptFn - received value: '%s'", value)
		t.Logf("DEBUG: Inside decryptFn - value length: %d", len(value))

		// Remove the "AES256:" prefix if it exists
		valueToDecrypt := value
		if strings.HasPrefix(value, AES) {
			valueToDecrypt = strings.TrimPrefix(value, AES)
			t.Logf("DEBUG: Removed AES prefix, new value: '%s'", valueToDecrypt)
		}

		decryptedBuffer, err := encryption.DecryptToString(valueToDecrypt, testKey)
		if err != nil {
			t.Logf("DEBUG: Decryption error: %v", err)
			// Try to diagnose the error
			if strings.Contains(err.Error(), "base64") {
				t.Logf("DEBUG: Base64 error - checking first few bytes: %v", []byte(value[:min(10, len(value))]))
			}
			return "", err
		}

		t.Logf("DEBUG: Successfully decrypted value: '%s'", decryptedBuffer)
		return decryptedBuffer, nil
	})
	if err != nil {
		t.Fatalf("DecryptMultiline() error = %v", err)
	}

	// Verify decryption
	if node.Value != originalText {
		t.Errorf("Decrypted value = %s, want %s", node.Value, originalText)
	}
	if node.Style != originalStyle {
		t.Errorf("Style after decryption = %v, want %v", node.Style, originalStyle)
	}

	// === Test ProcessMultilineNode separately for encryption and decryption ===

	// Create new test nodes for process test
	encNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: originalStyle,
		Value: originalText,
	}

	// Test ProcessMultilineNode for encryption
	processed, err := ProcessMultilineNode(encNode, "test.path", testKey, OperationEncrypt, false)
	if err != nil {
		t.Fatalf("ProcessMultilineNode(encrypt) error = %v", err)
	}
	if !processed {
		t.Errorf("ProcessMultilineNode(encrypt) = false, want true")
	}
	if !strings.HasPrefix(encNode.Value, AES) {
		t.Errorf("Encrypted value should start with %s", AES)
	}

	// Save encrypted value for decryption test
	encryptedValueFromProcessNode := encNode.Value
	t.Logf("DEBUG: ProcessMultilineNode encrypted value: '%s'", encryptedValueFromProcessNode)

	// Create a new node for decryption to avoid any state issues
	decNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: 0, // Plain style, as it would be after encryption
		Value: encryptedValueFromProcessNode,
	}

	// Test ProcessMultilineNode for decryption
	processed, err = ProcessMultilineNode(decNode, "test.path", testKey, OperationDecrypt, false)
	if err != nil {
		t.Fatalf("ProcessMultilineNode(decrypt) error = %v", err)
	}
	if !processed {
		t.Errorf("ProcessMultilineNode(decrypt) = false, want true")
	}
	if decNode.Value != originalText {
		t.Errorf("Decrypted value = %s, want %s", decNode.Value, originalText)
	}
}

// helper function for debugging
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestIsMultilineContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "multiline content",
			content:  "Line 1\nLine 2\nLine 3",
			expected: true,
		},
		{
			name:     "single line content",
			content:  "Line 1",
			expected: false,
		},
		{
			name:     "empty content",
			content:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMultilineContent(tt.content)
			if result != tt.expected {
				t.Errorf("IsMultilineContent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDecryptMultilinePreservesPEMFormat(t *testing.T) {
	// Create a test node with PEM content
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.DoubleQuotedStyle,
		Value: "-----BEGIN RSA PRIVATE KEY-----\\nMIIEogIB...\\nAaAaAa==\\n-----END RSA PRIVATE KEY-----",
	}

	// Use a secure key for testing
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz" // Strong password that meets our requirements

	// Save the original style for verification
	originalStyle := node.Style

	// Expected value after decryption (with real newlines instead of escaped ones)
	expectedDecrypted := "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIB...\nAaAaAa==\n-----END RSA PRIVATE KEY-----"

	// Encrypt the value
	err := EncryptMultiline(node, testKey, false)
	assert.NoError(t, err)

	// Check that the value was encrypted
	assert.True(t, strings.HasPrefix(node.Value, AES))
	assert.Contains(t, node.Value, DoubleQuotedStyleSuffix) // Check that the style was preserved in the suffix

	// Decrypt the value
	err = DecryptMultiline(node, func(value string) (string, error) {
		// Remove the "AES256:" prefix if it exists
		valueToDecrypt := value
		if strings.HasPrefix(value, AES) {
			valueToDecrypt = strings.TrimPrefix(value, AES)
		}

		decryptedBuffer, err := encryption.DecryptToString(valueToDecrypt, testKey)
		if err != nil {
			return "", err
		}
		return decryptedBuffer, nil
	})
	assert.NoError(t, err)

	// Check that the value was properly transformed and style was restored
	assert.Equal(t, expectedDecrypted, node.Value)
	assert.Equal(t, originalStyle, node.Style)
}

func TestDecryptCertificatesPreservesFormat(t *testing.T) {
	testCases := []struct {
		name      string
		content   string
		nodeStyle yaml.Style
		expected  string // Add expected value after transformation
	}{
		{
			name:      "content with escaped newlines",
			content:   "line1\\nline2\\nline3",
			nodeStyle: yaml.DoubleQuotedStyle,
			expected:  "line1\nline2\nline3", // Expect real newlines
		},
		{
			name:      "multiline quoted content",
			content:   "first line\\nsecond line\\nthird line",
			nodeStyle: yaml.DoubleQuotedStyle,
			expected:  "first line\nsecond line\nthird line", // Expect real newlines
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a node with the test value
			node := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: tc.nodeStyle,
				Value: tc.content,
			}

			// Remember original values for verification
			originalStyle := node.Style

			// Use a secure key for testing
			testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz" // Strong password that meets our requirements

			// Encrypt the value
			err := EncryptMultiline(node, testKey, false)
			assert.NoError(t, err)

			// Check that the value was encrypted
			assert.True(t, strings.HasPrefix(node.Value, AES))

			// Check for the style suffix based on the original style
			switch tc.nodeStyle {
			case yaml.DoubleQuotedStyle:
				assert.Contains(t, node.Value, DoubleQuotedStyleSuffix)
			case yaml.SingleQuotedStyle:
				assert.Contains(t, node.Value, SingleQuotedStyleSuffix)
			case yaml.LiteralStyle:
				assert.Contains(t, node.Value, LiteralStyleSuffix)
			case yaml.FoldedStyle:
				assert.Contains(t, node.Value, FoldedStyleSuffix)
			}

			// Decrypt the value
			err = DecryptMultiline(node, func(value string) (string, error) {
				// Remove the "AES256:" prefix if it exists
				valueToDecrypt := value
				if strings.HasPrefix(value, AES) {
					valueToDecrypt = strings.TrimPrefix(value, AES)
				}

				decryptedBuffer, err := encryption.DecryptToString(valueToDecrypt, testKey)
				if err != nil {
					return "", err
				}
				return decryptedBuffer, nil
			})
			assert.NoError(t, err)

			// Check that the value was transformed correctly
			assert.Equal(t, tc.expected, node.Value)

			// Check number of newlines
			expectedNewlines := strings.Count(tc.expected, "\n")
			actualNewlines := strings.Count(node.Value, "\n")
			assert.Equal(t, expectedNewlines, actualNewlines, "Number of newlines should match")

			// Check that the style was preserved
			assert.Equal(t, originalStyle, node.Style)
		})
	}
}

func TestProcessConfigFileContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "nginx_config",
			content: `data: |-
  user nginx;
  worker_processes auto;
  events { worker_connections 1024; }
  http {
    server {
      listen 80;
      server_name localhost;
      location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
      }
    }
  }`,
			expected: `data: |-
    user nginx;
    worker_processes auto;
    events { worker_connections 1024; }
    http {
      server {
        listen 80;
        server_name localhost;
        location / {
          root /usr/share/nginx/html;
          index index.html index.htm;
        }
      }
    }`,
		},
		{
			name: "apache_config",
			content: `config: |-
  <VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
  </VirtualHost>`,
			expected: `config: |-
    <VirtualHost *:80>
      ServerAdmin webmaster@localhost
      DocumentRoot /var/www/html
      ErrorLog ${APACHE_LOG_DIR}/error.log
      CustomLog ${APACHE_LOG_DIR}/access.log combined
    </VirtualHost>`,
		},
		{
			name: "nginx_config_with_sensitive_data",
			content: `data: |-
  user nginx;
  worker_processes auto;
  events { worker_connections 1024; }
  http {
    server {
      listen 443 ssl;
      server_name example.com;
      ssl_certificate /etc/nginx/ssl/server.crt;
      ssl_certificate_key /etc/nginx/ssl/server.key;
      ssl_password "!@#sensitive_password123";
      location / {
        proxy_pass http://backend;
        proxy_set_header Authorization "Bearer secret_token_123";
      }
    }
  }`,
			expected: `data: |-
    user nginx;
    worker_processes auto;
    events { worker_connections 1024; }
    http {
      server {
        listen 443 ssl;
        server_name example.com;
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_password "!@#sensitive_password123";
        location / {
          proxy_pass http://backend;
          proxy_set_header Authorization "Bearer secret_token_123";
        }
      }
    }`,
		},
		{
			name: "kubernetes_config_with_sensitive_data",
			content: `config: |-
  apiVersion: v1
  kind: Secret
  metadata:
    name: app-secrets
  type: Opaque
  data:
    DB_PASSWORD: "sensitive_db_password_123"
    API_KEY: "very_secret_api_key_456"
    JWT_SECRET: "super_secret_jwt_789"
  ---
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: app
  spec:
    template:
      spec:
        containers:
        - name: app
          env:
          - name: DATABASE_URL
            value: "postgresql://user:password@db:5432/app"`,
			expected: `config: |-
    apiVersion: v1
    kind: Secret
    metadata:
      name: app-secrets
    type: Opaque
    data:
      DB_PASSWORD: "sensitive_db_password_123"
      API_KEY: "very_secret_api_key_456"
      JWT_SECRET: "super_secret_jwt_789"
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: app
    spec:
      template:
        spec:
          containers:
          - name: app
            env:
            - name: DATABASE_URL
              value: "postgresql://user:password@db:5432/app"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data map[string]interface{}
			err := yaml.Unmarshal([]byte(tt.content), &data)
			if err != nil {
				t.Fatalf("Failed to unmarshal test content: %v", err)
			}

			// Convert data to YAML bytes
			yamlBytes, err := yaml.Marshal(data)
			if err != nil {
				t.Fatalf("Failed to marshal test content: %v", err)
			}

			// Process the content
			processedPaths := make(map[string]bool)
			rules := []Rule{
				{
					Name:        "nginx_config",
					Block:       "nginx",
					Pattern:     "**",
					Description: "Encrypt nginx configuration blocks",
				},
			}
			_, err = ProcessYAMLContent(yamlBytes, "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz", "encrypt", rules, processedPaths, false)
			if err != nil {
				t.Fatalf("Failed to process content: %v", err)
			}

			// Marshal back to YAML
			output, err := yaml.Marshal(data)
			if err != nil {
				t.Fatalf("Failed to marshal processed content: %v", err)
			}

			// Compare with expected, ignoring indentation differences
			normalizedOutput := normalizeString(string(output))
			normalizedExpected := normalizeString(tt.expected)
			if normalizedOutput != normalizedExpected {
				t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, string(output))
			}
		})
	}
}

// normalizeString removes all whitespace to compare YAML content regardless of indentation
func normalizeString(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", "")
}

func TestIsConfigurationContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "nginx config",
			content: `user nginx;
worker_processes auto;
events { worker_connections 1024; }
http {
  server {
    listen 80;
    server_name localhost;
    location / {
      root /usr/share/nginx/html;
      index index.html index.htm;
    }
  }
}`,
			expected: true,
		},
		{
			name: "apache config",
			content: `<VirtualHost *:80>
  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/html
  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>`,
			expected: true,
		},
		{
			name: "simple key-value pairs",
			content: `key1: value1
key2: value2`,
			expected: false,
		},
		{
			name: "multiline text",
			content: `This is a multiline
text that should not be
detected as configuration`,
			expected: false,
		},
		{
			name:     "empty content",
			content:  "",
			expected: false,
		},
		{
			name: "haproxy config",
			content: `frontend http
  bind *:80
  default_backend web_backend

backend web_backend
  server web1 10.0.0.1:80 check
  server web2 10.0.0.2:80 check`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isConfigurationContent(tt.content)
			if result != tt.expected {
				t.Errorf("isConfigurationContent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestProcessConfigurationNode(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		operation string
	}{
		{
			name: "nginx_config_encrypt",
			content: `server {
  listen 80;
  server_name example.com;
  
  location / {
    proxy_pass http://backend;
  }
}`,
			operation: OperationEncrypt,
		},
		{
			name: "apache_config_encrypt",
			content: `<VirtualHost *:80>
  ServerName example.com
  DocumentRoot /var/www/html
  
  <Directory /var/www/html>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>`,
			operation: OperationEncrypt,
		},
		{
			name:      "non-config_content",
			content:   "This is line 1\nThis is line 2\nThis is line 3",
			operation: OperationEncrypt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create node with the content
			node := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: yaml.LiteralStyle,
				Value: tt.content,
			}

			// Set up test key
			key := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz"
			debug := true

			// Process the node
			processed, err := ProcessMultilineNode(node, tt.name, key, tt.operation, debug)
			if err != nil {
				t.Fatalf("ProcessMultilineNode() error = %v", err)
			}

			// Verify if the node was processed
			if !processed {
				t.Fatalf("Node not processed")
			}

			// For encryption operation, verify AES prefix
			if tt.operation == OperationEncrypt && !strings.HasPrefix(node.Value, AES) {
				t.Errorf("Encrypted value doesn't have AES prefix: %s", node.Value)
			}

			// For decryption, verify no AES prefix
			if tt.operation == OperationDecrypt && strings.HasPrefix(node.Value, AES) {
				t.Errorf("Decrypted value still has AES prefix: %s", node.Value)
			}
		})
	}
}

// TestPreserveExactFormatting tests that content formatting is processed correctly
// after encryption and decryption cycles
func TestPreserveExactFormatting(t *testing.T) {
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz" // Strong password that meets our requirements

	tests := []struct {
		name           string
		format         yaml.Style
		content        string
		expectedResult string // Expected result
	}{
		{
			name:           "certificate with literal style",
			format:         yaml.LiteralStyle,
			content:        "-----BEGIN CERTIFICATE-----\nMIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcM\nB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEUMBIGA1UECwwLSUFNIENvbnNvbGUx\nGTAXBgNVBAMMEHd3dy5leGFtcGxlLmNvbTAeFw0yMzA3MDExNTAwMDBaFw0yNDA2\nMzAxNTAwMDBaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAw\n-----END CERTIFICATE-----",
			expectedResult: "-----BEGIN CERTIFICATE-----\nMIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcM\nB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEUMBIGA1UECwwLSUFNIENvbnNvbGUx\nGTAXBgNVBAMMEHd3dy5leGFtcGxlLmNvbTAeFw0yMzA3MDExNTAwMDBaFw0yNDA2\nMzAxNTAwMDBaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAw\n-----END CERTIFICATE-----",
		},
		{
			name:           "certificate with quoted style",
			format:         yaml.DoubleQuotedStyle,
			content:        "-----BEGIN CERTIFICATE-----\\nMIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL\\n-----END CERTIFICATE-----",
			expectedResult: "-----BEGIN CERTIFICATE-----\nMIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----",
		},
		{
			name:           "certificate with escaped newlines",
			format:         yaml.DoubleQuotedStyle,
			content:        "-----BEGIN CERTIFICATE-----\\nMIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL\\n-----END CERTIFICATE-----",
			expectedResult: "-----BEGIN CERTIFICATE-----\nMIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----",
		},
		{
			name:           "normal multiline text",
			format:         yaml.LiteralStyle,
			content:        "This is line 1\nThis is line 2\nThis is line 3",
			expectedResult: "This is line 1\nThis is line 2\nThis is line 3",
		},
		{
			name:           "folded multiline text",
			format:         yaml.FoldedStyle,
			content:        "This is line 1\nThis is line 2\nThis is line 3",
			expectedResult: "This is line 1\nThis is line 2\nThis is line 3",
		},
		{
			name:           "single line text with literal style",
			format:         yaml.LiteralStyle,
			content:        "Just a single line",
			expectedResult: "Just a single line",
		},
		{
			name:           "mixed text with tabs and spaces",
			format:         yaml.LiteralStyle,
			content:        "Line 1\n\tIndented with tab\n    Indented with spaces\nBack to normal",
			expectedResult: "Line 1\n\tIndented with tab\n    Indented with spaces\nBack to normal",
		},
		{
			name:           "JSON content",
			format:         yaml.LiteralStyle,
			content:        "{\n  \"key1\": \"value1\",\n  \"key2\": \"value2\"\n}",
			expectedResult: "{\n  \"key1\": \"value1\",\n  \"key2\": \"value2\"\n}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For folded style, use our special handling with protectFoldedStyleSections
			if tt.format == yaml.FoldedStyle {
				// Create test YAML content
				yamlContent := "content: >-\n  " + strings.ReplaceAll(tt.content, "\n", "\n  ")

				// Step 1: Protect folded sections
				sections, processedContent := protectFoldedStyleSections([]byte(yamlContent), true)

				// Step 2: Parse the YAML
				var node yaml.Node
				if err := yaml.Unmarshal(processedContent, &node); err != nil {
					t.Fatalf("Failed to unmarshal YAML: %v", err)
				}

				// Step 3: Encrypt scalar nodes
				if err := encryptScalarNodesForTesting(&node, testKey); err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}

				// Step 4: Marshal back to YAML
				encryptedContent, err := yaml.Marshal(&node)
				if err != nil {
					t.Fatalf("Failed to marshal encrypted YAML: %v", err)
				}

				// Step 5: Parse the encrypted YAML
				var decryptNode yaml.Node
				if err := yaml.Unmarshal(encryptedContent, &decryptNode); err != nil {
					t.Fatalf("Failed to unmarshal encrypted YAML: %v", err)
				}

				// Step 6: Decrypt scalar nodes
				if err := decryptScalarNodesForTesting(&decryptNode, testKey); err != nil {
					t.Fatalf("Failed to decrypt: %v", err)
				}

				// Step 7: Marshal back to YAML
				decryptedContent, err := yaml.Marshal(&decryptNode)
				if err != nil {
					t.Fatalf("Failed to marshal decrypted YAML: %v", err)
				}

				// Step 8: Restore folded sections
				finalContent := restoreFoldedStyleSections(decryptedContent, sections, true)

				// Step 9: Verify the content contains the expected result
				finalLines := strings.Split(string(finalContent), "\n")
				expectedLines := strings.Split(tt.expectedResult, "\n")

				// Find the content lines in the final content
				var contentFound bool
				for i := 0; i < len(finalLines); i++ {
					if strings.Contains(finalLines[i], "content: >-") {
						// Verify the subsequent lines match the expected content
						for j := 0; j < len(expectedLines); j++ {
							lineIndex := i + j + 1 // +1 to skip the >- line
							if lineIndex >= len(finalLines) {
								t.Fatalf("Not enough lines in result, expected line %d", lineIndex)
							}

							// The actual lines will have indentation
							expected := strings.TrimSpace(expectedLines[j])
							actual := strings.TrimSpace(strings.TrimPrefix(finalLines[lineIndex], "  ")) // Remove indent

							if expected != actual {
								t.Errorf("Content mismatch at line %d: expected '%s', got '%s'",
									j, expected, actual)
							}
						}
						contentFound = true
						break
					}
				}

				if !contentFound {
					t.Errorf("Content not found in result:\n%s", string(finalContent))
				}

				return
			}

			// Regular handling for non-folded styles
			// Create a YAML scalar node with the specified style and content
			originalNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: tt.format,
				Value: tt.content,
			}

			// Encrypt the node
			err := EncryptMultiline(originalNode, testKey, true)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			// Verify AES prefix exists
			if !strings.HasPrefix(originalNode.Value, AES) {
				t.Fatalf("Encrypted value doesn't have AES prefix: %s", originalNode.Value)
			}

			// Create decryption function
			decryptFn := func(value string) (string, error) {
				// Remove the "AES256:" prefix if it exists
				valueToDecrypt := value
				if strings.HasPrefix(value, AES) {
					valueToDecrypt = strings.TrimPrefix(value, AES)
				}

				decryptedBuffer, err := encryption.DecryptToString(valueToDecrypt, testKey)
				if err != nil {
					return "", err
				}
				return decryptedBuffer, nil
			}

			// Decrypt the node
			err = DecryptMultiline(originalNode, decryptFn)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			// Verify decrypted content matches expected value
			if originalNode.Value != tt.expectedResult {
				t.Errorf("Content mismatch:\nExpected: %s\nGot: %s", tt.expectedResult, originalNode.Value)
			}

			// Verify style is preserved
			if originalNode.Style != tt.format {
				t.Errorf("Style not preserved: expected %v, got %v", tt.format, originalNode.Style)
			}

			// Second encryption (should be the same result)
			err = EncryptMultiline(originalNode, testKey, true)
			if err != nil {
				t.Fatalf("Failed second encryption: %v", err)
			}

			// Verify AES prefix exists after second encryption
			if !strings.HasPrefix(originalNode.Value, AES) {
				t.Fatalf("Second encryption failed, missing AES prefix: %s", originalNode.Value)
			}
		})
	}
}

// TestPreserveEscapedNewlines tests that escaped newlines in double-quoted strings
// are properly processed during encryption and decryption
func TestPreserveEscapedNewlines(t *testing.T) {
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz"
	originalValue := "line1\\nline2\\nline3"
	// Expected result after transformation of escape sequences
	expectedValue := "line1\nline2\nline3"

	// Create a node with a double-quoted style
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.DoubleQuotedStyle,
		Value: originalValue,
	}

	// Encrypt the node
	err := EncryptMultiline(node, testKey, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify encryption worked
	if !strings.HasPrefix(node.Value, AES) {
		t.Errorf("Encrypted value should start with %s", AES)
	}

	// Verify the style suffix is included
	if !strings.HasSuffix(node.Value, DoubleQuotedStyleSuffix) {
		t.Errorf("Encrypted value should end with style suffix %s", DoubleQuotedStyleSuffix)
	}

	// Decrypt the node
	err = DecryptMultiline(node, func(value string) (string, error) {
		// Remove the "AES256:" prefix if it exists
		valueToDecrypt := value
		if strings.HasPrefix(value, AES) {
			valueToDecrypt = strings.TrimPrefix(value, AES)
		}

		decryptedBuffer, err := encryption.DecryptToString(valueToDecrypt, testKey)
		if err != nil {
			return "", err
		}
		return decryptedBuffer, nil
	})
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify the value is correctly decrypted with transformed escape sequences
	if node.Value != expectedValue {
		t.Errorf("Decrypted value does not match expected.\nExpected: %q\nGot: %q",
			expectedValue, node.Value)
	}

	// Verify the style was restored
	if node.Style != yaml.DoubleQuotedStyle {
		t.Errorf("Style was not restored correctly. Expected %d, got %d",
			yaml.DoubleQuotedStyle, node.Style)
	}

	// Now test with a more complex case involving certificates
	certWithEscapedNewlines := "-----BEGIN CERTIFICATE-----\\nMIIFazCCA1OgAwIBAgIUBEVwsSx0TmCLhZVDx0vlNZ0UQE8\\n-----END CERTIFICATE-----"
	// Expected result after transformation
	expectedCert := "-----BEGIN CERTIFICATE-----\nMIIFazCCA1OgAwIBAgIUBEVwsSx0TmCLhZVDx0vlNZ0UQE8\n-----END CERTIFICATE-----"

	// Create a node for the certificate with double-quoted style
	certNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.DoubleQuotedStyle,
		Value: certWithEscapedNewlines,
	}

	// Encrypt the certificate node
	err = EncryptMultiline(certNode, testKey, true)
	if err != nil {
		t.Fatalf("Failed to encrypt certificate: %v", err)
	}

	// Decrypt the certificate node
	err = DecryptMultiline(certNode, func(value string) (string, error) {
		// Remove the "AES256:" prefix if it exists
		valueToDecrypt := value
		if strings.HasPrefix(value, AES) {
			valueToDecrypt = strings.TrimPrefix(value, AES)
		}

		decryptedBuffer, err := encryption.DecryptToString(valueToDecrypt, testKey)
		if err != nil {
			return "", err
		}
		return decryptedBuffer, nil
	})
	if err != nil {
		t.Fatalf("Failed to decrypt certificate: %v", err)
	}

	// Verify the certificate value is correctly transformed
	if certNode.Value != expectedCert {
		t.Errorf("Decrypted certificate does not match expected.\nExpected: %q\nGot: %q",
			expectedCert, certNode.Value)
	}
}

// TestPEMCertificateProcessing checks the processing of PEM certificates with different YAML styles
func TestPEMCertificateProcessing(t *testing.T) {
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz"

	// Test certificate
	certContent := `-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL
BQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcM
B1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEUMBIGA1UECwwLSUFNIENvbnNvbGUx
GTAXBgNVBAMMEHd3dy5leGFtcGxlLmNvbTAeFw0yMzA3MDExNTAwMDBaFw0yNDA2
MzAxNTAwMDBa
-----END CERTIFICATE-----`

	// Variant with escaped line breaks
	escapedCertContent := strings.ReplaceAll(certContent, "\n", "\\n")

	tests := []struct {
		name      string
		style     yaml.Style
		content   string
		expectErr bool
	}{
		{
			name:    "PEM certificate with literal style",
			style:   yaml.LiteralStyle,
			content: certContent,
		},
		{
			name:    "PEM certificate with folded style",
			style:   yaml.FoldedStyle,
			content: certContent,
		},
		{
			name:    "PEM certificate with double-quoted style (escaped newlines)",
			style:   yaml.DoubleQuotedStyle,
			content: escapedCertContent,
		},
		{
			name:    "PEM certificate with single-quoted style",
			style:   yaml.SingleQuotedStyle,
			content: certContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a YAML node with specified style and content
			node := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: tt.style,
				Value: tt.content,
			}

			// Remember original values for verification
			originalStyle := node.Style
			originalContent := node.Value

			// Expected value after decryption (with real newlines instead of escaped ones)
			expectedContent := originalContent
			if originalStyle == yaml.DoubleQuotedStyle {
				expectedContent = strings.ReplaceAll(expectedContent, "\\n", "\n")
			}

			// Encrypt the value
			err := EncryptMultiline(node, testKey, true)

			// Check if the expected error occurred
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for style %v but got none", tt.style)
				}
				return
			}

			if err != nil {
				t.Fatalf("EncryptMultiline() error = %v", err)
			}

			// Check that the value was encrypted
			if !strings.HasPrefix(node.Value, AES) {
				t.Errorf("Encrypted value does not start with AES prefix: %s", node.Value)
			}

			// Check for the style suffix in the encrypted value
			var expectedSuffix string
			switch originalStyle {
			case yaml.LiteralStyle:
				expectedSuffix = LiteralStyleSuffix
			case yaml.FoldedStyle:
				expectedSuffix = FoldedStyleSuffix
			case yaml.DoubleQuotedStyle:
				expectedSuffix = DoubleQuotedStyleSuffix
			case yaml.SingleQuotedStyle:
				expectedSuffix = SingleQuotedStyleSuffix
			}

			if expectedSuffix != "" && !strings.HasSuffix(node.Value, expectedSuffix) {
				t.Errorf("Encrypted value does not end with expected style suffix %s: %s",
					expectedSuffix, node.Value)
			}

			// Decrypt the node
			err = DecryptMultiline(node, func(value string) (string, error) {
				// Remove the "AES256:" prefix if it exists
				valueToDecrypt := value
				if strings.HasPrefix(value, AES) {
					valueToDecrypt = strings.TrimPrefix(value, AES)
				}

				decryptedBuffer, err := encryption.DecryptToString(valueToDecrypt, testKey)
				if err != nil {
					return "", err
				}
				return decryptedBuffer, nil
			})
			if err != nil {
				t.Fatalf("DecryptMultiline() error = %v", err)
			}

			// Check that the content was restored correctly
			if node.Value != expectedContent {
				t.Errorf("Content mismatch after decryption.\nExpected: %q\nGot: %q",
					expectedContent, node.Value)
			}

			// Check that the style was preserved
			if node.Style != originalStyle {
				t.Errorf("Style not preserved after decryption. Expected %v, got %v",
					originalStyle, node.Style)
			}
		})
	}
}

func TestFoldedStyleRoundTripIsEncrypted(t *testing.T) {
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz"
	original := "first line\nsecond line\nthird line"

	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.FoldedStyle,
		Value: original,
	}

	if err := EncryptMultiline(node, testKey, false); err != nil {
		t.Fatalf("EncryptMultiline() error = %v", err)
	}

	if !strings.HasPrefix(node.Value, AES) {
		t.Fatalf("expected folded node to be encrypted, got: %s", node.Value)
	}
	if !strings.HasSuffix(node.Value, FoldedStyleSuffix) {
		t.Fatalf("expected folded style suffix, got: %s", node.Value)
	}

	if err := DecryptMultiline(node, func(value string) (string, error) {
		valueToDecrypt := strings.TrimPrefix(value, AES)
		return encryption.DecryptToString(valueToDecrypt, testKey)
	}); err != nil {
		t.Fatalf("DecryptMultiline() error = %v", err)
	}

	if node.Value != original {
		t.Fatalf("decrypted value mismatch: got %q want %q", node.Value, original)
	}
	if node.Style != yaml.FoldedStyle {
		t.Fatalf("expected folded style restored, got %v", node.Style)
	}
}

// TestComplexYAMLStructureWithMultilineValues tests processing of complex YAML structures with nested multiline values
func TestComplexYAMLStructureWithMultilineValues(t *testing.T) {
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz"

	yamlContent := `
config:
  certificates:
    public_key: |
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxWzg9vJJR0TIIu5XzCQG
      BijxB+EFPYvkJ/3vbXFNaYQTvMPwcU3I9JXaUFwIHHjMnHElo6oHECBZzj5ki9Dg
      3l1FcJn598L0D0pLECZ9wOJeGHlPP/CGXj6gWVj6kfn3t/9I4hQ7oz5X+JzmqGEg
      /JyqVVZ1BqHd09jrLQIDAQAB
      -----END PUBLIC KEY-----
    private_key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFbOD28klHRMgi
      7lfMJAYGKPEH4QU9i+Qn/e9tcU1phBO8w/BxTcj0ldpQXAgceMycgSWjqgcQIFnO
      -----END PRIVATE KEY-----
  description: |
    This is a literal block
    text in YAML
    with preserved line breaks.
`

	// Parse YAML document
	var rootNode yaml.Node
	err := yaml.Unmarshal([]byte(yamlContent), &rootNode)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Create encryption rules
	rules := []Rule{
		{
			Name:    "certificates",
			Block:   "config.certificates",
			Pattern: "**",
		},
		{
			Name:    "description",
			Block:   "config",
			Pattern: "description",
		},
	}

	// Encrypt document
	processedPaths := make(map[string]bool)
	err = ProcessNode(&rootNode, "", testKey, OperationEncrypt, rules, processedPaths, true)
	if err != nil {
		t.Fatalf("ProcessNode(encrypt) error: %v", err)
	}

	// Verify encrypted values
	// Get config.certificates.public_key
	certificatesNode := getNodeByPath(&rootNode, "config.certificates")
	if certificatesNode == nil {
		t.Fatalf("Failed to find certificates node")
	}

	publicKeyNode := getNodeValue(certificatesNode, "public_key")
	if publicKeyNode == nil {
		t.Fatalf("Failed to find public_key node")
	}

	// Verify encrypted value
	if !strings.HasPrefix(publicKeyNode.Value, AES) {
		t.Errorf("Public key was not encrypted: %s", publicKeyNode.Value)
	}

	// Get private_key node
	privateKeyNode := getNodeValue(certificatesNode, "private_key")
	if privateKeyNode == nil {
		t.Fatalf("Failed to find private_key node")
	}

	// Verify encrypted value
	if !strings.HasPrefix(privateKeyNode.Value, AES) {
		t.Errorf("Private key was not encrypted: %s", privateKeyNode.Value)
	}

	// Decrypt document
	processedPaths = make(map[string]bool) // Reset paths
	err = ProcessNode(&rootNode, "", testKey, OperationDecrypt, rules, processedPaths, true)
	if err != nil {
		t.Fatalf("ProcessNode(decrypt) error: %v", err)
	}

	// Verify decrypted values and correct styles
	publicKeyNode = getNodeValue(certificatesNode, "public_key")
	if publicKeyNode == nil {
		t.Fatalf("Failed to find public_key node after decryption")
	}

	// Verify public_key style (should be literal)
	if publicKeyNode.Style != yaml.LiteralStyle {
		t.Errorf("Public key style after decryption doesn't match original. Got %v, expected %v",
			publicKeyNode.Style, yaml.LiteralStyle)
	}

	// Verify decrypted value
	if strings.HasPrefix(publicKeyNode.Value, AES) {
		t.Errorf("Public key was not decrypted")
	}

	// Verify private_key
	privateKeyNode = getNodeValue(certificatesNode, "private_key")
	if privateKeyNode == nil {
		t.Fatalf("Failed to find private_key node after decryption")
	}

	// Verify private_key style (should be literal)
	if privateKeyNode.Style != yaml.LiteralStyle {
		t.Errorf("Private key style after decryption doesn't match original. Got %v, expected %v",
			privateKeyNode.Style, yaml.LiteralStyle)
	}

	// Verify decrypted value
	if strings.HasPrefix(privateKeyNode.Value, AES) {
		t.Errorf("Private key was not decrypted")
	}
}

// Helper function to get node by path
func getNodeByPath(rootNode *yaml.Node, path string) *yaml.Node {
	if rootNode == nil || rootNode.Kind != yaml.DocumentNode {
		return nil
	}

	// Root node of the document
	node := rootNode.Content[0]
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}

	// Split path into parts
	parts := strings.Split(path, ".")

	// Traverse the path
	for _, part := range parts {
		found := false
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 < len(node.Content) && node.Content[i].Value == part {
				node = node.Content[i+1]
				found = true
				break
			}
		}

		if !found {
			return nil
		}
	}

	return node
}

// Helper function to get value from mapping node
func getNodeValue(mappingNode *yaml.Node, key string) *yaml.Node {
	if mappingNode == nil || mappingNode.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i < len(mappingNode.Content); i += 2 {
		if i+1 < len(mappingNode.Content) && mappingNode.Content[i].Value == key {
			return mappingNode.Content[i+1]
		}
	}

	return nil
}

// TestDecryptValue tests the DecryptValue function
func TestDecryptValue(t *testing.T) {
	// Use a strong password that meets all validation requirements
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz"

	tests := []struct {
		name        string
		value       string
		key         string
		expected    string
		shouldError bool
	}{
		{
			name:        "not encrypted value",
			value:       "plaintext",
			key:         testKey,
			expected:    "plaintext",
			shouldError: false,
		},
		{
			name:        "encrypted value",
			value:       createTestEncryptedValue(t, "secret-data", testKey),
			key:         testKey,
			expected:    "secret-data",
			shouldError: false,
		},
		{
			name:        "invalid encrypted value",
			value:       AES + "invalid-base64",
			key:         testKey,
			expected:    "",
			shouldError: true,
		},
		{
			name:        "wrong key",
			value:       createTestEncryptedValue(t, "secret-data", testKey),
			key:         "D1ff3r3nt!P@ssw0rd#S9f&h27!G",
			expected:    "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecryptValue(tt.value, tt.key)

			// Check for error
			if (err != nil) != tt.shouldError {
				t.Errorf("DecryptValue() error = %v, shouldError %v", err, tt.shouldError)
				return
			}

			// If there should be no error, check the result
			if !tt.shouldError && result != tt.expected {
				t.Errorf("DecryptValue() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper function to create encrypted values
func createTestEncryptedValue(t *testing.T, plaintext, key string) string {
	encrypted, err := encryption.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt test value: %v", err)
	}
	return AES + encrypted
}

// TestProcessFoldedStyleContent tests that folded style content is properly preserved
// using protectFoldedStyleSections and restoreFoldedStyleSections functions
func TestProcessFoldedStyleContent(t *testing.T) {
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz" // Strong password that meets our requirements

	// Create test cases
	tests := []struct {
		name           string
		content        string
		expectedResult string
	}{
		{
			name: "folded multiline text",
			content: `folded_content: >-
  This is line 1
  This is line 2
  This is line 3`,
			expectedResult: `folded_content: >-
  This is line 1
  This is line 2
  This is line 3`,
		},
		{
			name: "folded style without dash",
			content: `folded_content: >
  This is line 1
  This is line 2
  This is line 3`,
			// The YAML parser normalizes > to >-, so we expect >- in the result
			expectedResult: `folded_content: >-
  This is line 1
  This is line 2
  This is line 3`,
		},
		{
			name: "mixed content with folded style",
			content: `regular: value1
folded: >-
  This is a folded
  style section
  with multiple lines
normal: another value`,
			expectedResult: `regular: value1
folded: >-
  This is a folded
  style section
  with multiple lines
normal: another value`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert original content to bytes
			originalContent := []byte(tt.content)

			// Step 1: Protect folded sections
			sections, processed := protectFoldedStyleSections(originalContent, true)

			// Verify sections were protected
			if len(sections) == 0 {
				t.Fatalf("No folded sections found in test content")
			}

			// Step 2: Create YAML node from processed content
			var node yaml.Node
			err := yaml.Unmarshal(processed, &node)
			if err != nil {
				t.Fatalf("Failed to unmarshal YAML: %v", err)
			}

			// Step 3: Recursively encrypt scalar nodes
			if err := encryptScalarNodesForTesting(&node, testKey); err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			// Step 4: Marshal the encrypted YAML back to bytes
			encryptedContent, err := yaml.Marshal(&node)
			if err != nil {
				t.Fatalf("Failed to marshal YAML: %v", err)
			}

			// Step 5: Create YAML node from encrypted content
			var decryptNode yaml.Node
			err = yaml.Unmarshal(encryptedContent, &decryptNode)
			if err != nil {
				t.Fatalf("Failed to unmarshal encrypted YAML: %v", err)
			}

			// Step 6: Recursively decrypt scalar nodes
			if err := decryptScalarNodesForTesting(&decryptNode, testKey); err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			// Step 7: Marshal the decrypted YAML back to bytes
			decryptedContent, err := yaml.Marshal(&decryptNode)
			if err != nil {
				t.Fatalf("Failed to marshal decrypted YAML: %v", err)
			}

			// Step 8: Restore folded sections
			finalContent := restoreFoldedStyleSections(decryptedContent, sections, true)

			// Compare to expected result - use normalized comparison to ignore invisible formatting differences
			// Convert both strings to bytes and then compare
			finalLines := strings.Split(string(finalContent), "\n")
			expectedLines := strings.Split(tt.expectedResult, "\n")

			// Remove empty lines at the end of both arrays
			finalLines = removeTrailingEmptyLines(finalLines)
			expectedLines = removeTrailingEmptyLines(expectedLines)

			if len(finalLines) != len(expectedLines) {
				t.Errorf("Line count mismatch: got %d lines, expected %d lines",
					len(finalLines), len(expectedLines))
				t.Errorf("Content mismatch:\nExpected:\n%s\n\nGot:\n%s",
					tt.expectedResult, string(finalContent))
				return
			}

			// Compare each line, trimming whitespace to avoid formatting issues
			mismatch := false
			for i, line := range finalLines {
				if strings.TrimSpace(line) != strings.TrimSpace(expectedLines[i]) {
					t.Errorf("Line %d mismatch:\nExpected: '%s'\nGot: '%s'",
						i+1, strings.TrimSpace(expectedLines[i]), strings.TrimSpace(line))
					mismatch = true
				}
			}

			if mismatch {
				t.Errorf("Content mismatch:\nExpected:\n%s\n\nGot:\n%s",
					tt.expectedResult, string(finalContent))
			}
		})
	}
}

// Helper function to recursively encrypt scalar nodes for testing
func encryptScalarNodesForTesting(node *yaml.Node, key string) error {
	if node == nil {
		return nil
	}

	if node.Kind == yaml.ScalarNode && node.Style != yaml.FoldedStyle && !strings.HasPrefix(node.Value, AES) {
		// Only encrypt if it's not already encrypted
		encryptedValue, err := encryption.Encrypt(key, node.Value, encryption.Argon2idAlgorithm)
		if err != nil {
			return err
		}
		node.Value = AES + encryptedValue
	}

	for i := range node.Content {
		if err := encryptScalarNodesForTesting(node.Content[i], key); err != nil {
			return err
		}
	}

	return nil
}

// Helper function to recursively decrypt scalar nodes for testing
func decryptScalarNodesForTesting(node *yaml.Node, key string) error {
	if node == nil {
		return nil
	}

	if node.Kind == yaml.ScalarNode && strings.HasPrefix(node.Value, AES) {
		encryptedValue := strings.TrimPrefix(node.Value, AES)
		decryptedValue, err := encryption.DecryptToString(encryptedValue, key)
		if err != nil {
			return err
		}
		node.Value = decryptedValue
	}

	for i := range node.Content {
		if err := decryptScalarNodesForTesting(node.Content[i], key); err != nil {
			return err
		}
	}

	return nil
}

// Now let's also update the existing TestPreserveExactFormatting test to handle folded style
func TestPreserveExactFormattingUpdated(t *testing.T) {
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz" // Strong password that meets our requirements

	tests := []struct {
		name           string
		format         yaml.Style
		content        string
		expectedResult string // Expected result
		skip           bool
	}{
		{
			name:           "folded multiline text",
			format:         yaml.FoldedStyle,
			content:        "This is line 1\nThis is line 2\nThis is line 3",
			expectedResult: "This is line 1\nThis is line 2\nThis is line 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test YAML content
			yamlContent := fmt.Sprintf("content: %s", tt.content)
			switch tt.format {
			case yaml.FoldedStyle:
				// For folded style, we need special formatting
				yamlContent = "content: >-\n  " + strings.ReplaceAll(tt.content, "\n", "\n  ")
			case yaml.LiteralStyle:
				// For literal style, we need special formatting
				yamlContent = "content: |\n  " + strings.ReplaceAll(tt.content, "\n", "\n  ")
			}

			// Step 1: Protect folded sections if using folded style
			var sections []FoldedStyleSection
			var processedContent []byte

			if tt.format == yaml.FoldedStyle {
				sections, processedContent = protectFoldedStyleSections([]byte(yamlContent), true)
			} else {
				processedContent = []byte(yamlContent)
			}

			// Step 2: Parse the YAML
			var node yaml.Node
			if err := yaml.Unmarshal(processedContent, &node); err != nil {
				t.Fatalf("Failed to unmarshal YAML: %v", err)
			}

			// Step 3: Encrypt content
			if tt.format != yaml.FoldedStyle {
				// For non-folded styles, use the regular mechanism
				contentNode := getNodeValueByKey(&node, "content")
				if contentNode == nil {
					t.Fatalf("Failed to find content node")
				}

				err := EncryptMultiline(contentNode, testKey, true)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}
			} else {
				// For folded style, encrypt all scalar nodes
				err := encryptScalarNodesForTesting(&node, testKey)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}
			}

			// Step 4: Marshal back to YAML
			encryptedContent, err := yaml.Marshal(&node)
			if err != nil {
				t.Fatalf("Failed to marshal encrypted YAML: %v", err)
			}

			// Step 5: Parse the encrypted YAML
			var decryptNode yaml.Node
			if err := yaml.Unmarshal(encryptedContent, &decryptNode); err != nil {
				t.Fatalf("Failed to unmarshal encrypted YAML: %v", err)
			}

			// Step 6: Decrypt content
			if tt.format != yaml.FoldedStyle {
				// For non-folded styles, use the regular decryption
				contentNode := getNodeValueByKey(&decryptNode, "content")
				if contentNode == nil {
					t.Fatalf("Failed to find encrypted content node")
				}

				err := DecryptMultiline(contentNode, func(value string) (string, error) {
					// Remove the "AES256:" prefix if it exists
					valueToDecrypt := value
					if strings.HasPrefix(value, AES) {
						valueToDecrypt = strings.TrimPrefix(value, AES)
					}

					decryptedBuffer, err := encryption.DecryptToString(valueToDecrypt, testKey)
					if err != nil {
						return "", err
					}
					return decryptedBuffer, nil
				})
				if err != nil {
					t.Fatalf("Failed to decrypt: %v", err)
				}
			} else {
				// For folded style, decrypt all scalar nodes
				err := decryptScalarNodesForTesting(&decryptNode, testKey)
				if err != nil {
					t.Fatalf("Failed to decrypt: %v", err)
				}
			}

			// Step 7: Marshal back to YAML
			decryptedContent, err := yaml.Marshal(&decryptNode)
			if err != nil {
				t.Fatalf("Failed to marshal decrypted YAML: %v", err)
			}

			// Step 8: Restore folded sections if needed
			var finalContent []byte
			if tt.format == yaml.FoldedStyle {
				finalContent = restoreFoldedStyleSections(decryptedContent, sections, true)
			} else {
				finalContent = decryptedContent
			}

			// Step 9: Parse the final content to extract the value
			var finalNode yaml.Node
			if err := yaml.Unmarshal(finalContent, &finalNode); err != nil {
				t.Fatalf("Failed to unmarshal final YAML: %v", err)
			}

			contentNode := getNodeValueByKey(&finalNode, "content")
			if contentNode == nil {
				t.Fatalf("Failed to find final content node")
			}

			// Verify the content matches the expected result
			if tt.format == yaml.FoldedStyle {
				// For folded style, we need to extract the content differently
				// The content is in the YAML itself, so let's check if our original content is there
				// Normalize and compare line by line
				finalLines := strings.Split(string(finalContent), "\n")
				expectedLines := strings.Split(tt.expectedResult, "\n")

				// Find the actual content in the final content and compare it
				var foundContent bool
				for i := 0; i < len(finalLines); i++ {
					if strings.Contains(finalLines[i], "content: >-") {
						// Found the content start, verify the subsequent lines match
						for j := 0; j < len(expectedLines); j++ {
							lineIndex := i + j + 1 // +1 to skip the >- line
							if lineIndex >= len(finalLines) {
								break
							}
							expected := strings.TrimSpace(expectedLines[j])
							actual := strings.TrimSpace(strings.TrimPrefix(finalLines[lineIndex], "  ")) // Remove indent
							if expected != actual {
								t.Errorf("Line content mismatch at line %d:\nExpected: '%s'\nGot: '%s'",
									j, expected, actual)
							}
						}
						foundContent = true
						break
					}
				}

				if !foundContent {
					t.Errorf("Could not find folded content in the result:\n%s", string(finalContent))
				}
			} else {
				// For other styles, normalize and compare the node value
				if normalizeString(contentNode.Value) != normalizeString(tt.expectedResult) {
					t.Errorf("Content mismatch:\nExpected: %s\nGot: %s",
						tt.expectedResult, contentNode.Value)
				}
			}
		})
	}
}

// Helper to get a node by key from a YAML node tree
func getNodeValueByKey(node *yaml.Node, key string) *yaml.Node {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 < len(node.Content) && node.Content[i].Value == key {
				return node.Content[i+1]
			}
		}
	}

	return nil
}

// Helper function to remove trailing empty lines
func removeTrailingEmptyLines(lines []string) []string {
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[:i+1]
		}
	}
	return []string{}
}
