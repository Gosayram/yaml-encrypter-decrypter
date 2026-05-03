package processor

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/encryption"
	"gopkg.in/yaml.v3"
)

// nodePool provides a pool of yaml.Node objects to reduce GC pressure
var nodePool = sync.Pool{
	New: func() interface{} {
		return &yaml.Node{}
	},
}

// acquireNode gets a yaml.Node from the pool
func acquireNode() *yaml.Node {
	return nodePool.Get().(*yaml.Node)
}

// releaseNode returns a yaml.Node to the pool after resetting its fields
func releaseNode(n *yaml.Node) {
	if n == nil {
		return
	}
	// Reset all fields to avoid data leakage between uses
	n.Kind = 0
	n.Style = 0
	n.Tag = ""
	n.Value = ""
	n.Anchor = ""
	n.Alias = nil
	// Reuse the underlying slice capacity but clear the elements
	for i := range n.Content {
		n.Content[i] = nil
	}
	n.Content = n.Content[:0]
	n.HeadComment = ""
	n.LineComment = ""
	n.FootComment = ""
	n.Line = 0
	n.Column = 0

	nodePool.Put(n)
}

// deepCopyNode creates a deep copy of a YAML node using the object pool
func deepCopyNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}

	newNode := acquireNode()
	newNode.Kind = node.Kind
	newNode.Style = node.Style
	newNode.Tag = node.Tag
	newNode.Value = node.Value
	newNode.Anchor = node.Anchor
	newNode.Alias = deepCopyNode(node.Alias)
	newNode.HeadComment = node.HeadComment
	newNode.LineComment = node.LineComment
	newNode.FootComment = node.FootComment
	newNode.Line = node.Line
	newNode.Column = node.Column

	if len(node.Content) > 0 {
		newNode.Content = make([]*yaml.Node, len(node.Content))
		for i, child := range node.Content {
			newNode.Content[i] = deepCopyNode(child)
		}
	}

	return newNode
}

// releaseNodeTree recursively releases a node and its children to the pool
func releaseNodeTree(node *yaml.Node) {
	if node == nil {
		return
	}
	for _, child := range node.Content {
		releaseNodeTree(child)
	}
	releaseNode(node)
}

// detectAlgorithm tries to identify the algorithm used in the encrypted value
func detectAlgorithm(encryptedValue string) string {
	if !strings.HasPrefix(encryptedValue, AES) {
		return UnknownAlgorithm
	}

	data := strings.TrimPrefix(encryptedValue, AES)
	if meta, err := encryption.ExtractMetadata(data); err == nil && meta.Algorithm != "" {
		return string(meta.Algorithm)
	}

	return UnknownAlgorithm
}

// logNodeDetails logs node details
func logNodeDetails(node *yaml.Node, path string, debug bool) {
	debugLog(debug, "Processing node at path %s with style %v", path, node.Style)
	debugLog(debug, "Node value length: %d", len(node.Value))
	if len(node.Value) > previewNodeChars {
		debugLog(debug, "Node value first %d chars: '%s'", previewNodeChars, node.Value[:previewNodeChars])
	} else {
		debugLog(debug, "Node value: '%s'", node.Value)
	}
}

// shouldSkipNode checks if a node should be skipped
func shouldSkipNode(node *yaml.Node, debug bool) bool {
	if node == nil {
		return true
	}
	if node.Style == yaml.FlowStyle || node.Value == "" {
		debugLog(debug, "Skipping node with flow style or empty value")
		return true
	}
	return false
}

// clearNodeData recursively clears sensitive data from the node
func clearNodeData(node *yaml.Node) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if strings.HasPrefix(node.Value, AES) {
			node.Value = ""
		}
	case yaml.SequenceNode, yaml.MappingNode:
		for _, child := range node.Content {
			clearNodeData(child)
		}
	}
}

// maskNodeValues recursively masks encrypted values in YAML nodes
func maskNodeValues(node *yaml.Node, debug bool) *yaml.Node {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if strings.HasPrefix(node.Value, AES) {
			node.Value = maskEncryptedValue(node.Value, debug)
		}
		return node
	case yaml.SequenceNode:
		for _, child := range node.Content {
			maskNodeValues(child, debug)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 < len(node.Content) {
				maskNodeValues(node.Content[i+1], debug)
			}
		}
	}
	return node
}

func isValidOperation(operation string) bool {
	return operation == OperationEncrypt || operation == OperationDecrypt
}

// EvaluateCondition evaluates a condition with caching
func EvaluateCondition(condition string, value interface{}) bool {
	if condition == "" {
		return true
	}

	// Check if condition is a wildcard pattern
	if strings.Contains(condition, "*") {
		re, err := getCompiledRegex(wildcardToRegex(condition))
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", value))
	}

	// Direct comparison for non-wildcard conditions
	return fmt.Sprintf("%v", value) == condition
}
