package processor

import (
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesFromPattern(t *testing.T) {
	tempDir := t.TempDir()

	// Create some dummy rule files
	ruleContent := `
rules:
  - name: test_rule
    block: test
    pattern: ".*"
    action: encrypt
`

	err := os.WriteFile(filepath.Join(tempDir, "rule1.yml"), []byte(ruleContent), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(tempDir, "rule2.yml"), []byte(ruleContent), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(tempDir, "other.txt"), []byte("not rules"), 0644)
	assert.NoError(t, err)

	t.Run("Glob pattern", func(t *testing.T) {
		rules, err := loadRulesFromPattern("*.yml", tempDir, false)
		assert.NoError(t, err)
		assert.Len(t, rules, 2)
	})

	t.Run("Range pattern", func(t *testing.T) {
		rules, err := loadRulesFromPattern("rule[1-2].yml", tempDir, false)
		assert.NoError(t, err)
		assert.Len(t, rules, 2)
	})

	t.Run("Range pattern out of bounds", func(t *testing.T) {
		rules, err := loadRulesFromPattern("rule[1-5].yml", tempDir, false)
		assert.NoError(t, err)
		assert.Len(t, rules, 2) // Should only find 1 and 2
	})

	t.Run("Invalid glob pattern", func(t *testing.T) {
		_, err := loadRulesFromPattern("[*", tempDir, false)
		assert.Error(t, err)
	})

	t.Run("Invalid range bounds", func(t *testing.T) {
		rules, err := loadRulesFromPattern("rule[a-2].yml", tempDir, false)
		assert.NoError(t, err) // It falls back to glob and returns empty
		assert.Len(t, rules, 0)
	})
}

func TestNeedsQuoting(t *testing.T) {
	assert.True(t, needsQuoting(""))
	assert.True(t, needsQuoting("true"))
	assert.True(t, needsQuoting("123"))
	assert.True(t, needsQuoting("1.23"))
	assert.True(t, needsQuoting("~"))
	assert.True(t, needsQuoting("null"))
	assert.True(t, needsQuoting("has space"))
	assert.True(t, needsQuoting("starts: with"))
	assert.True(t, needsQuoting("contains#hash"))
	assert.False(t, needsQuoting("normal_string"))
}

func TestReadWriteYAMLWithBuffer(t *testing.T) {
	_, err := readYAMLWithBuffer("/non/existent/file.yml")
	assert.Error(t, err)

	err = writeYAMLWithBuffer("/invalid/path/file.yml", nil)
	assert.Error(t, err)
}

func TestLoadRulesFromFile_Variants(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("encryption.rules structure", func(t *testing.T) {
		path := filepath.Join(tempDir, "enc_rules.yml")
		content := `
encryption:
  rules:
    - name: r1
      block: b1
      pattern: p1
      action: encrypt
`
		err := os.WriteFile(path, []byte(content), 0644)
		assert.NoError(t, err)
		rules, err := loadRulesFromFile(path, false)
		assert.NoError(t, err)
		assert.Len(t, rules, 1)
	})

	t.Run("non-yaml extension", func(t *testing.T) {
		path := filepath.Join(tempDir, "rules.txt")
		err := os.WriteFile(path, []byte("rules"), 0644)
		assert.NoError(t, err)
		_, err = loadRulesFromFile(path, false)

		assert.Error(t, err)
	})

	t.Run("invalid yaml", func(t *testing.T) {
		path := filepath.Join(tempDir, "bad.yml")
		err := os.WriteFile(path, []byte(" - ["), 0644)
		assert.NoError(t, err)
		_, err = loadRulesFromFile(path, false)

		assert.Error(t, err)
	})
}

func TestFixBase64Padding_Coverage(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", fixBase64Padding("", false))
	})
	t.Run("non-printable", func(t *testing.T) {
		assert.Equal(t, "YWJj", fixBase64Padding("YWJj\x00", false))
	})
	t.Run("invalid remainder 1", func(t *testing.T) {
		// len 5 -> rem 1
		assert.Equal(t, "abcde===", fixBase64Padding("abcde", false))
	})
	t.Run("special case YWJj", func(t *testing.T) {
		assert.Equal(t, "YWJj", fixBase64Padding("YWJj", false))
	})
}

func TestProcessNode_Complex(t *testing.T) {
	yamlData := `
key1: value1
key2:
  - item1
  - item2
key3:
  subkey1: subvalue1
`
	var node yaml.Node
	err := yaml.Unmarshal([]byte(yamlData), &node)
	assert.NoError(t, err)

	rules := []Rule{
		{Name: "r1", Block: "key1", Action: "encrypt"},
		{Name: "r2", Block: "key2", Action: "encrypt"},
		{Name: "r3", Block: "key3", Action: "encrypt"},
	}

	processedPaths := make(map[string]bool)
	err = ProcessNode(&node, "", "this-is-a-long-enough-key-for-validation", OperationEncrypt, rules, processedPaths, false)

	assert.NoError(t, err)
}

func TestProcessMappingNode_Invalid(t *testing.T) {
	node := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "key"},
		},
	}
	err := processMappingNode(node, "", "this-is-a-long-enough-key-for-validation", OperationEncrypt, nil, nil, false)
	assert.Error(t, err)

	node2 := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.MappingNode}, // Non-scalar key
			{Kind: yaml.ScalarNode, Value: "val"},
		},
	}
	err = processMappingNode(node2, "", "this-is-a-long-enough-key-for-validation", OperationEncrypt, nil, nil, false)
	assert.NoError(t, err) // Should skip the non-scalar key
}

func TestDecryptNodeValue_Error(t *testing.T) {
	_, err := decryptNodeValue("AES256:invalid-base64", "HighlySecureAndUniquePass-2024!", false)
	assert.Error(t, err)
}

func TestShouldSkipNode_Nil(t *testing.T) {
	assert.True(t, shouldSkipNode(nil, false))
}

func TestIsExplicitIncludeRuleFile_Coverage(t *testing.T) {
	assert.True(t, isExplicitIncludeRuleFile("rules.yml"))
	assert.False(t, isExplicitIncludeRuleFile("rules*.yml"))
	assert.False(t, isExplicitIncludeRuleFile("   "))
}

func TestProcessSequenceNode_Coverage(t *testing.T) {
	node := &yaml.Node{
		Kind: yaml.SequenceNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "item1"},
		},
	}
	err := processSequenceNode(node, "path", "HighlySecureAndUniquePass-2024!", OperationEncrypt, nil, nil, false)
	assert.NoError(t, err)
}

func TestEvaluateCondition_Coverage(t *testing.T) {
	assert.True(t, EvaluateCondition("val", "val"))
	assert.False(t, EvaluateCondition("other", "val"))
	assert.True(t, EvaluateCondition("", "val"))
}

func TestCheckDuplicateRules_Coverage(t *testing.T) {
	rules := []Rule{
		{Name: "r1"},
		{Name: "r1"},
	}
	checkDuplicateRules(rules, true)
}

func TestProcessScalarNode_DecryptCoverage(t *testing.T) {
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "AES256:v2;ts=123;alg=argon2id;YWJj",
	}
	rules := []Rule{{Block: "key", Action: "encrypt"}}
	err := processScalarNode(node, "key", "HighlySecureAndUniquePass-2024!", OperationDecrypt, rules, nil, true)
	assert.Error(t, err)
}

func TestValidateRules_Error(t *testing.T) {
	rules := []Rule{{Name: "r1", Action: "invalid"}}
	err := ValidateRules(rules, false)
	assert.Error(t, err)
}

func TestResolveIncludePattern_Abs(t *testing.T) {
	abs := "/tmp/rules.yml"
	assert.Equal(t, abs, resolveIncludePattern(abs, "/etc/config.yml"))
}

func TestClearNodeData_NilCoverage(t *testing.T) {
	clearNodeData(nil)
}

func TestLoadAdditionalRules_NilConfig(t *testing.T) {
	_, _, err := LoadAdditionalRules(nil, "", false)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestLoadIncludedRules_EmptyCoverage(t *testing.T) {
	res, err := loadIncludedRules(nil, "", false, "")
	assert.NoError(t, err)
	assert.Nil(t, res)

	res, err = loadIncludedRules([]string{}, "", false, "")
	assert.NoError(t, err)
	assert.Nil(t, res)
}

func TestResolveConfigPath_CustomCoverage(t *testing.T) {
	abs, _ := filepath.Abs("custom.yml")
	assert.Equal(t, abs, resolveConfigPath("custom.yml", false))
}

func TestProcessScalarNode_SkipCoverage(t *testing.T) {
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "val"}
	rules := []Rule{{Block: "key", Action: "skip"}}
	err := processScalarNode(node, "key", "", OperationEncrypt, rules, nil, false)
	assert.NoError(t, err)
}

func TestProcessNode_NilAndUnknown(t *testing.T) {
	err := processNode(nil, "path", "key", OperationEncrypt, nil, nil, false)
	assert.NoError(t, err)

	unknownNode := &yaml.Node{Kind: 0xFF}
	err = processNode(unknownNode, "path", "key", OperationEncrypt, nil, nil, false)
	assert.NoError(t, err)
}

func TestProcessScalarNode_AliasAndProcessed(t *testing.T) {
	aliasNode := &yaml.Node{Kind: yaml.AliasNode}
	rules := []Rule{{Block: "path", Action: "encrypt"}}
	err := processScalarNode(aliasNode, "path", "key", OperationEncrypt, rules, nil, false)
	assert.NoError(t, err)

	scalarNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "val"}
	processed := map[string]bool{"path": true}
	err = processScalarNode(scalarNode, "path", "key", OperationEncrypt, rules, processed, false)
	assert.NoError(t, err)
}

func TestEncryptScalarNode_AlreadyEncryptedAndError(t *testing.T) {
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "AES256:already"}
	err := encryptScalarNode(node, "path", "key", nil, false)
	assert.NoError(t, err)

	// To trigger encryption error, we can use a very weak password if validation is on,
	// but encryption.Encrypt usually validates password first.
	// If we use a valid password but something else fails...
	// Actually encryption.Encrypt fails if password strength validation is enabled and fails.
	err = encryptScalarNode(&yaml.Node{Value: "val"}, "path", "weak", nil, false)
	assert.Error(t, err)
}

func TestDecryptScalarNode_NotEncryptedAndError(t *testing.T) {
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "not_encrypted"}
	err := decryptScalarNode(node, "path", "key", nil, false)
	assert.NoError(t, err)

	nodeEnc := &yaml.Node{Kind: yaml.ScalarNode, Value: "AES256:invalid"}
	err = decryptScalarNode(nodeEnc, "path", "HighlySecureAndUniquePass-2024!", nil, false)
	assert.Error(t, err)
}

func TestDecryptNodeValue_EdgeCases(t *testing.T) {
	// Too short
	val, err := decryptNodeValue("short", "key", false)
	assert.NoError(t, err)
	assert.Equal(t, "short", val)

	// Too short with suffix
	val, err = decryptNodeValue("abc|plain", "key", false)
	assert.NoError(t, err)
	assert.Equal(t, "abc|plain", val)

	// Base64 padding fix
	// We need a string that is valid base64 but missing padding
	// "data" -> "ZGF0YQ=="
	// "ZGF0YQ" is missing padding
	// But DecryptToString might still fail because it's not a valid encrypted payload.
	// However, it will hit the fixBase64Padding branch.
	_, err = decryptNodeValue("v2;ts=123;alg=argon2id;ZGF0YQ", "HighlySecureAndUniquePass-2024!", false)
	assert.Error(t, err)
}

func TestShouldSkipNode_FlowStyle(t *testing.T) {
	node := &yaml.Node{Style: yaml.FlowStyle}
	assert.True(t, shouldSkipNode(node, false))
}

func TestProcessScalarNodeForDiff_ErrorsAndSensitive(t *testing.T) {
	// Sensitive value
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "yed_encrypt_password=secret"}
	processScalarNodeForDiff(node, "key", OperationEncrypt, false, true)
	// Should be masked in debug output, but node.Value might change if encryption succeeds

	// Encryption error (weak password)
	nodeEnc := &yaml.Node{Kind: yaml.ScalarNode, Value: "val"}
	processScalarNodeForDiff(nodeEnc, "weak", OperationEncrypt, false, true)

	// Decryption error
	nodeDec := &yaml.Node{Kind: yaml.ScalarNode, Value: "AES256:invalid"}
	processScalarNodeForDiff(nodeDec, "HighlySecureAndUniquePass-2024!", OperationDecrypt, false, true)
}

func TestWriteYAMLWithBuffer_Error(t *testing.T) {
	node := &yaml.Node{Kind: yaml.DocumentNode}
	err := writeYAMLWithBuffer("/non/existent/dir/file.yml", node)
	assert.Error(t, err)
}

func TestProcessMappingNode_InvalidCoverage(t *testing.T) {
	// Odd number of content items
	node := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: "key"}}}
	err := processMappingNode(node, "path", "key", OperationEncrypt, nil, nil, false)
	assert.Error(t, err)

	// Non-scalar key
	node2 := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.MappingNode}, {Kind: yaml.ScalarNode, Value: "val"},
	}}
	err = processMappingNode(node2, "path", "key", OperationEncrypt, nil, nil, false)
	assert.NoError(t, err)
}

func TestProcessMultilineStyleNode_ErrorAndNotProcessed(t *testing.T) {
	// To trigger error, we can use an invalid encrypted value in decrypt mode
	node := &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.LiteralStyle, Value: "AES256:invalid"}
	err := processMultilineStyleNode(node, "path", "HighlySecureAndUniquePass-2024!", OperationDecrypt, nil, true)
	assert.Error(t, err)

	// To trigger not processed, we can use a non-encrypted value in decrypt mode
	node2 := &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.LiteralStyle, Value: "plain"}
	err = processMultilineStyleNode(node2, "path", "key", OperationDecrypt, nil, true)
	assert.NoError(t, err)
}

func TestReadYAMLWithBuffer_ErrorsCoverage(t *testing.T) {
	// Open error
	_, err := readYAMLWithBuffer("/non/existent/file.yml")
	assert.Error(t, err)

	// Decode error
	tmpfile, _ := os.CreateTemp("", "invalid.yml")
	defer func() {
		err := os.Remove(tmpfile.Name())
		assert.NoError(t, err)
	}()

	_ = os.WriteFile(tmpfile.Name(), []byte("invalid: yaml: :"), 0644)
	_, err = readYAMLWithBuffer(tmpfile.Name())
	assert.Error(t, err)
}

func TestShowDiff_EdgeCasesCoverage(t *testing.T) {
	// Nil data
	showDiff(nil, "key", OperationEncrypt, false, true, []Rule{{Block: "b"}})

	// Empty content
	showDiff(&yaml.Node{}, "key", OperationEncrypt, false, true, []Rule{{Block: "b"}})

	// Empty rules
	showDiff(&yaml.Node{Content: []*yaml.Node{{}}}, "key", OperationEncrypt, false, true, nil)
}

func TestLoadRulesFromPattern_RangeAndNonYaml(t *testing.T) {
	// Non-yaml file
	tmpfile, _ := os.CreateTemp("", "notyaml.txt")
	defer func() {
		err := os.Remove(tmpfile.Name())
		assert.NoError(t, err)
	}()

	res, err := loadRulesFromPattern(tmpfile.Name(), "", false)
	assert.NoError(t, err)
	assert.Empty(t, res)

	// Range syntax
	dir, _ := os.MkdirTemp("", "rules_range")
	defer func() {
		err := os.RemoveAll(dir)
		assert.NoError(t, err)
	}()

	_ = os.WriteFile(filepath.Join(dir, "rule1.yml"), []byte("rules:\n  - block: b1"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "rule2.yml"), []byte("rules:\n  - block: b2"), 0644)

	pattern := filepath.Join(dir, "rule[1-2].yml")
	res, err = loadRulesFromPattern(pattern, "", true)
	assert.NoError(t, err)
	assert.Len(t, res, 2)
}

func TestPrintDiff_NilCoverage(t *testing.T) {
	printDiff(nil, nil, false, false, "")
}

func TestProcessNodeForDiff_NilAndUnknown(t *testing.T) {
	processNodeForDiff(nil, "key", OperationEncrypt, false, false)

	unknownNode := &yaml.Node{Kind: 0xFF}
	processNodeForDiff(unknownNode, "key", OperationEncrypt, false, false)
}

func TestNeedsQuoting_Coverage(t *testing.T) {
	assert.True(t, needsQuoting(""))
	assert.True(t, needsQuoting("\n"))
	assert.True(t, needsQuoting(" "))
	assert.True(t, needsQuoting("true"))
	assert.True(t, needsQuoting("123"))
	assert.True(t, needsQuoting("1.23"))
	assert.True(t, needsQuoting("#comment"))
	assert.False(t, needsQuoting("simple"))
}

func TestRenderInlineScalar_StylesCoverage(t *testing.T) {
	assert.Equal(t, "\"val\"", renderInlineScalar("val", yaml.DoubleQuotedStyle))
	assert.Equal(t, "'val''s'", renderInlineScalar("val's", yaml.SingleQuotedStyle))
}

func TestByteIndexAtColumn_InvalidUTF8Coverage(t *testing.T) {
	// 0xFF is invalid start of UTF-8
	line := string([]byte{0xFF, 'a', 'b'})
	assert.Equal(t, 1, byteIndexAtColumn(line, 2))
}

func TestLoadRulesFromPattern_GlobErrorCoverage(t *testing.T) {
	_, err := loadRulesFromPattern("[", "", false)
	assert.Error(t, err)
}

func TestIsRuleValidationEnabled_Coverage(t *testing.T) {
	config := &Config{}
	assert.True(t, isRuleValidationEnabled(config))

	val := false
	config.Encryption.ValidateRules = &val
	assert.False(t, isRuleValidationEnabled(config))

	valTrue := true
	config.Encryption.ValidateRules = &valTrue
	assert.True(t, isRuleValidationEnabled(config))
}

func TestProcessYAMLWithExclusions_EdgeCasesCoverage(t *testing.T) {
	// Nil node
	err := processYAMLWithExclusions(nil, "key", OperationEncrypt, Rule{}, "", nil, nil, false)
	assert.NoError(t, err)

	// Invalid operation
	err = processYAMLWithExclusions(&yaml.Node{}, "key", "invalid", Rule{}, "", nil, nil, false)
	assert.Error(t, err)

	// Nil maps and unknown kind
	err = processYAMLWithExclusions(&yaml.Node{Kind: 0xFF}, "key", OperationEncrypt, Rule{}, "", nil, nil, false)
	assert.NoError(t, err)
}

func TestEncryptScalarNode_LiteralStyleCoverage(t *testing.T) {
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "val", Style: yaml.LiteralStyle}
	err := encryptScalarNode(node, "path", "HighlySecureAndUniquePass-2024!", nil, false)
	assert.NoError(t, err)
	assert.Contains(t, node.Value, "|literal")
}
