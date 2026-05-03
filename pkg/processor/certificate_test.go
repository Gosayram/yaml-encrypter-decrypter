package processor

import (
	"strings"
	"testing"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// TestCertificateFormatting is a comprehensive test for certificate handling
// with different YAML formatting styles
func TestCertificateFormatting(t *testing.T) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting TestCertificateFormatting")

	// Test key for encryption/decryption - using a stronger key that meets requirements
	testKey := "S9f&h27!Gp*3K5^LmZ#qR8@tUvWxYz" // Strong password with uppercase, lowercase, numbers and special chars

	// Sample certificate content
	sampleCert := `-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL
BQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcM
B1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEUMBIGA1UECwwLSUFNIENvbnNvbGUx
GTAXBgNVBAMMEHd3dy5leGFtcGxlLmNvbQ==
-----END CERTIFICATE-----`

	// Same certificate with escaped newlines for double-quoted style
	escapedCert := strings.ReplaceAll(sampleCert, "\n", "\\n")

	// For double-quoted style, we expect the result to be with actual newlines
	// after encryption and decryption (this is how YAML processes escaped sequences)
	expectedDoubleQuotedResult := sampleCert

	// Create a YAML node tree with different certificate formatting styles
	yamlData := map[string]interface{}{
		"certificates": map[string]interface{}{
			"literal_style": sampleCert,
			"quoted_style":  escapedCert,
			"nested": map[string]interface{}{
				"another_cert": sampleCert,
			},
		},
	}

	// Convert to YAML
	yamlBytes, err := yaml.Marshal(yamlData)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	// Parse YAML to get node tree for setting styles
	var root yaml.Node
	err = yaml.Unmarshal(yamlBytes, &root)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Apply different styles to certificate nodes
	// Navigate to the certificates mapping
	certsNode := root.Content[0].Content[1] // root -> document -> mapping -> "certificates" -> mapping

	// Find and set styles for certificate nodes
	for i := 0; i < len(certsNode.Content); i += 2 {
		keyNode := certsNode.Content[i]
		valueNode := certsNode.Content[i+1]

		switch keyNode.Value {
		case "literal_style":
			valueNode.Style = yaml.LiteralStyle // |
		case "quoted_style":
			valueNode.Style = yaml.DoubleQuotedStyle // "..."
		case "nested":
			// Find the nested cert
			nestedMapping := valueNode
			for j := 0; j < len(nestedMapping.Content); j += 2 {
				if nestedMapping.Content[j].Value == "another_cert" {
					nestedMapping.Content[j+1].Style = yaml.FoldedStyle // >
				}
			}
		}
	}

	// Convert back to YAML bytes with styles
	styledBytes, err := yaml.Marshal(&root)
	if err != nil {
		t.Fatalf("Failed to marshal styled data: %v", err)
	}

	// Print the original YAML for debug
	t.Logf("Original YAML:\n%s", string(styledBytes))

	// Encrypt the content
	rules := []Rule{
		{
			Name:        "certs-rule",
			Block:       "certificates",
			Pattern:     "**",
			Description: "Encrypt all certificates",
		},
	}
	processedPaths := make(map[string]bool)
	debug := true

	// Encrypt using the function that handles folded style properly
	encryptedBytes, err := ProcessYAMLContentWithFoldedStyle(styledBytes, testKey, OperationEncrypt, rules, processedPaths, debug)
	if err != nil {
		t.Fatalf("Error in encryption: %v", err)
	}

	t.Logf("Encrypted YAML:\n%s", string(encryptedBytes))

	// Now decrypt the content
	decryptedBytes, err := ProcessYAMLContentWithFoldedStyle(encryptedBytes, testKey, OperationDecrypt, rules, make(map[string]bool), debug)
	if err != nil {
		t.Fatalf("Error in decryption: %v", err)
	}

	t.Logf("Decrypted YAML:\n%s", string(decryptedBytes))

	// Parse the decrypted YAML to extract specific nodes for comparison
	var decryptedRoot yaml.Node
	err = yaml.Unmarshal(decryptedBytes, &decryptedRoot)
	if err != nil {
		t.Fatalf("Failed to unmarshal decrypted YAML: %v", err)
	}

	// Extract values for verification
	decryptedLiteralStyle := getNodeValueByPath(&decryptedRoot, "certificates.literal_style")
	decryptedQuotedStyle := getNodeValueByPath(&decryptedRoot, "certificates.quoted_style")
	decryptedNestedCert := getNodeValueByPath(&decryptedRoot, "certificates.nested.another_cert")

	// Verify the content - for literal style, should match exactly
	if decryptedLiteralStyle != sampleCert {
		t.Errorf("Decrypted literal style content doesn't match original:\nExpected: %q\nGot: %q", sampleCert, decryptedLiteralStyle)
	}

	// For double-quoted style, expect the version with actual newlines
	if decryptedQuotedStyle != expectedDoubleQuotedResult {
		t.Errorf("Decrypted double-quoted style content doesn't match expected:\nExpected: %q\nGot: %q", expectedDoubleQuotedResult, decryptedQuotedStyle)
	}

	// For folded style (in nested), no encryption should have happened
	if decryptedNestedCert != sampleCert {
		t.Errorf("Nested certificate with folded style should be unchanged:\nExpected: %q\nGot: %q", sampleCert, decryptedNestedCert)
	}

	// Also verify style preservation
	var originalRoot yaml.Node
	err = yaml.Unmarshal(styledBytes, &originalRoot)
	if err != nil {
		t.Fatalf("Failed to unmarshal original for style check: %v", err)
	}

	// Check that styles are preserved
	literalStyleNode := getTestNodeByPath(&decryptedRoot, "certificates.literal_style")
	quotedStyleNode := getTestNodeByPath(&decryptedRoot, "certificates.quoted_style")
	nestedCertNode := getTestNodeByPath(&decryptedRoot, "certificates.nested.another_cert")

	if literalStyleNode != nil && literalStyleNode.Style != yaml.LiteralStyle {
		t.Errorf("Literal style not preserved. Expected %d, got %d", yaml.LiteralStyle, literalStyleNode.Style)
	}

	if quotedStyleNode != nil && quotedStyleNode.Style != yaml.DoubleQuotedStyle {
		t.Errorf("Double-quoted style not preserved. Expected %d, got %d", yaml.DoubleQuotedStyle, quotedStyleNode.Style)
	}

	if nestedCertNode != nil && nestedCertNode.Style != yaml.FoldedStyle {
		t.Errorf("Folded style not preserved. Expected %d, got %d", yaml.FoldedStyle, nestedCertNode.Style)
	}
}

// getNodeValueByPath retrieves a node's value by traversing the given path
func getNodeValueByPath(rootNode *yaml.Node, path string) string {
	node := getTestNodeByPath(rootNode, path)
	if node != nil {
		return node.Value
	}
	return ""
}

// getTestNodeByPath retrieves a node by traversing the given path specifically for tests
func getTestNodeByPath(rootNode *yaml.Node, path string) *yaml.Node {
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
