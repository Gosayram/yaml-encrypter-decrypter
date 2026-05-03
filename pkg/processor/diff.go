package processor

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/awnumar/memguard"
	"gopkg.in/yaml.v3"
)

// ── ANSI colour helpers ────────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
	ansiYellow = "\033[33m"
	ansiDim    = "\033[2m"
	sepWidth   = 60
)

// colourEnabled controls ANSI output. Disabled when writing to non-tty (file,
// buffer in tests) or when NO_COLOR / TERM=dumb env vars are set.
var colourEnabled atomic.Bool

func init() {
	colourEnabled.Store(isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb")
}

// isTerminal is a lightweight tty check that avoids importing golang.org/x/term.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func colour(code, s string) string {
	if !colourEnabled.Load() {
		return s
	}
	return code + s + ansiReset
}

func red(s string) string    { return colour(ansiRed, s) }
func green(s string) string  { return colour(ansiGreen, s) }
func cyan(s string) string   { return colour(ansiCyan, s) }
func bold(s string) string   { return colour(ansiBold, s) }
func yellow(s string) string { return colour(ansiYellow, s) }
func dim(s string) string    { return colour(ansiDim, s) }

// ── Output writer ──────────────────────────────────────────────────────────────

var diffOutput io.Writer

// SetDiffOutput configures where diff output is written (tests use a buffer).
// Colour is automatically disabled when w is not *os.File pointing to a tty.
func SetDiffOutput(w io.Writer) {
	diffOutput = w
	// Disable colour when output is not a real terminal.
	if f, ok := w.(*os.File); ok {
		colourEnabled.Store(isTerminal(f) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb")
	} else {
		colourEnabled.Store(false)
	}
}

func getDiffOutput() io.Writer {
	if diffOutput == nil {
		return os.Stdout
	}
	return diffOutput
}

// ── Secure flag ────────────────────────────────────────────────────────────────

// unsecureDiffLog is shared with isSensitiveValue so it can consult the flag
// without an extra parameter.
var unsecureDiffLog atomic.Bool

// ── diffStats tracks counters printed in the summary line ─────────────────────

type diffStats struct {
	changed int
	masked  int
}

// ── showDiff ───────────────────────────────────────────────────────────────────

// showDiff displays differences between original and encrypted/decrypted values.
func showDiff(data *yaml.Node, key, operation string, unsecureDiff bool, debug bool, rules []Rule) {
	if data == nil || len(data.Content) == 0 {
		debugLog(debug, "showDiff: data is nil or empty")
		return
	}

	unsecureDiffLog.Store(unsecureDiff)
	debugLog(debug, "Starting showDiff with operation: %s, unsecureDiff: %v", operation, unsecureDiff)

	if unsecureDiff {
		_, _ = fmt.Fprintln(getDiffOutput(),
			yellow("⚠  WARNING: unsecure diff mode – sensitive data may be shown"))
	}

	if len(rules) == 0 {
		debugLog(debug, "No rules defined, no encryption will be performed")
		return
	}

	// Deep copies so we never mutate the caller's node tree.
	originalData := deepCopyNode(data)
	encryptedData := deepCopyNode(data)
	defer func() {
		releaseNodeTree(originalData)
		releaseNodeTree(encryptedData)
	}()

	// For encrypt: keep originalData as plaintext (no processing needed).
	// For decrypt: keep originalData as the encrypted input (no processing).
	if operation == OperationEncrypt {
		processNodeForDiff(originalData.Content[0], key, operation, true, debug)
	}

	// Identify paths excluded by action:none rules.
	excludedPaths := make(map[string]bool)
	for _, rule := range rules {
		if normalizedRuleAction(rule.Action) == ActionNone {
			debugLog(debug, "Marking paths for exclusion based on rule: %s", rule.Name)
			if err := markExcludedPaths(encryptedData.Content[0], rule, "", excludedPaths, debug); err != nil {
				debugLog(debug, "Error marking excluded paths: %v", err)
			}
		}
	}

	// Apply encryption/decryption rules to the "processed" copy.
	for _, rule := range rules {
		action := normalizedRuleAction(rule.Action)
		shouldProcess := action == ActionEncrypt || operation == OperationDecrypt
		if !shouldProcess {
			continue
		}
		debugLog(debug, "Processing rule: %s", rule.Name)
		if err := processYAMLWithExclusions(
			encryptedData.Content[0], key, operation, rule, "",
			make(map[string]bool), excludedPaths, debug,
		); err != nil {
			debugLog(debug, "Error processing YAML: %v", err)
		}
	}

	// Print the header banner.
	printDiffHeader(operation)

	// Walk the two trees and emit coloured lines.
	stats := &diffStats{}
	printDiff(originalData.Content[0], encryptedData.Content[0], debug, unsecureDiff, "", stats)

	// Print summary footer.
	printDiffFooter(stats)

	debugLog(debug, "Finished showDiff")
}

// ── Header / footer ────────────────────────────────────────────────────────────

func printDiffHeader(operation string) {
	w := getDiffOutput()
	sep := strings.Repeat("─", sepWidth)
	_, _ = fmt.Fprintln(w, dim(sep))

	opLabel := "encrypt"
	if operation == OperationDecrypt {
		opLabel = "decrypt"
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", bold("YAML diff"), dim("(operation: "+opLabel+")"))

	_, _ = fmt.Fprintf(w, "  %s  original value\n", red("―"))
	_, _ = fmt.Fprintf(w, "  %s  new value\n", green("+"))
	_, _ = fmt.Fprintln(w, dim(sep))
}

func printDiffFooter(stats *diffStats) {
	w := getDiffOutput()
	sep := strings.Repeat("─", sepWidth)
	_, _ = fmt.Fprintln(w, dim(sep))

	summary := fmt.Sprintf("%d field(s) changed", stats.changed)
	if stats.masked > 0 {
		summary += fmt.Sprintf(", %d value(s) masked", stats.masked)
	}
	_, _ = fmt.Fprintln(w, dim(summary))
}

// ── processNodeForDiff (scalar / sequence / mapping) ──────────────────────────

// processNodeForDiff recursively applies the operation to a node copy.
func processNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool) {
	if node == nil {
		debugLog(debug, "processNodeForDiff: received nil node")
		return
	}
	debugLog(debug, "processNodeForDiff: Processing node kind=%v", node.Kind)

	switch node.Kind {
	case yaml.ScalarNode:
		processScalarNodeForDiff(node, key, operation, isOriginal, debug)
	case yaml.SequenceNode:
		for i, child := range node.Content {
			debugLog(debug, "processNodeForDiff: sequence item %d", i)
			processNodeForDiff(child, key, operation, isOriginal, debug)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			processNodeForDiff(node.Content[i+1], key, operation, isOriginal, debug)
		}
	default:
		debugLog(debug, "processNodeForDiff: unsupported node kind: %v", node.Kind)
	}
}

// processScalarNodeForDiff encrypts or decrypts a scalar value in-place.
func processScalarNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool) {
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	if keyBuf == nil {
		log.Printf("Failed to create secure buffer for key")
		return
	}
	defer keyBuf.Destroy()

	valueBuf := memguard.NewBufferFromBytes([]byte(node.Value))
	if valueBuf == nil {
		log.Printf("Failed to create secure buffer for node value")
		return
	}
	defer valueBuf.Destroy()

	rawValue := string(valueBuf.Bytes())

	// Mask in debug output.
	displayValue := rawValue
	if isSensitiveValue(displayValue) ||
		strings.Contains(strings.ToLower(rawValue), "yed_encrypt_password") ||
		strings.Contains(strings.ToLower(rawValue), "password=") {
		displayValue = MaskedValue
	}
	debugLog(debug, "processNodeForDiff: scalar value='%s' isOriginal=%v", displayValue, isOriginal)

	if isOriginal {
		return // original copy is never mutated
	}

	rawKey := string(keyBuf.Bytes())
	debugKey := rawKey
	if len(debugKey) > minKeyLength {
		debugKey = "****" + debugKey[len(debugKey)-4:]
	}

	switch {
	case operation == OperationEncrypt && !strings.HasPrefix(rawValue, AES):
		enc, err := encryption.Encrypt(rawKey, rawValue)
		if err != nil {
			debugLog(debug, "processNodeForDiff: encrypt error: %v", err)
			return
		}
		node.Value = AES + enc
		debugLog(debug, "processNodeForDiff: encrypted (key suffix %s)", debugKey)

	case operation == OperationDecrypt && strings.HasPrefix(rawValue, AES):
		dec, err := encryption.DecryptToString(strings.TrimPrefix(rawValue, AES), rawKey)
		if err != nil {
			debugLog(debug, "processNodeForDiff: decrypt error: %v", err)
			return
		}
		node.Value = dec
		debugLog(debug, "processNodeForDiff: decrypted (key suffix %s)", debugKey)
	}
}

// ── isSensitiveValue ──────────────────────────────────────────────────────────

// isSensitiveValue reports whether a plaintext value should be masked.
func isSensitiveValue(value string) bool {
	lowered := strings.ToLower(value)
	if strings.Contains(lowered, "password") || strings.Contains(lowered, "yed_encryption_key") {
		return true
	}
	if unsecureDiffLog.Load() {
		return false
	}
	return !strings.HasPrefix(value, AES) && len(value) > MinEncryptedLength
}

// ── printDiff tree-walker ──────────────────────────────────────────────────────

func printDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string, stats *diffStats) {
	if original == nil || processed == nil {
		return
	}
	switch original.Kind {
	case yaml.MappingNode:
		printMappingDiff(original, processed, debug, unsecureDiff, path, stats)
	case yaml.SequenceNode:
		printSequenceDiff(original, processed, debug, unsecureDiff, path, stats)
	case yaml.ScalarNode:
		printScalarDiff(original, processed, debug, unsecureDiff, path, stats)
	}
}

func printMappingDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string, stats *diffStats) {
	for i := 0; i+1 < len(original.Content) && i+1 < len(processed.Content); i += 2 {
		keyNode := original.Content[i]
		var newPath string
		if path == "" {
			newPath = keyNode.Value
		} else {
			newPath = path + "." + keyNode.Value
		}
		printDiff(original.Content[i+1], processed.Content[i+1], debug, unsecureDiff, newPath, stats)
	}
}

func printSequenceDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string, stats *diffStats) {
	for i := 0; i < len(original.Content) && i < len(processed.Content); i++ {
		newPath := fmt.Sprintf("%s[%d]", path, i)
		printDiff(original.Content[i], processed.Content[i], debug, unsecureDiff, newPath, stats)
	}
}

// printScalarDiff emits a coloured unified-diff style block for one changed field.
//
// Output format:
//
//	handlers.user.password:           ← bold cyan path
//	  [L12] ― AES256:abc…xyz          ← red  (original)
//	  [L12] + plaintext               ← green (processed)
func printScalarDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string, stats *diffStats) {
	if original == nil || processed == nil {
		return
	}

	origVal := original.Value
	procVal := processed.Value

	if origVal == procVal {
		return // no change – skip
	}

	stats.changed++

	// ── masking ────────────────────────────────────────────────────────────────
	wasMasked := false
	if !unsecureDiff {
		origVal, wasMasked = applyMask(origVal, debug, path)
		procVal, _ = applyMask(procVal, debug, path)
	}
	if wasMasked {
		stats.masked++
	}

	// ── emit lines ─────────────────────────────────────────────────────────────
	w := getDiffOutput()
	_, _ = fmt.Fprintf(w, "%s\n", bold(cyan(path+":")))
	_, _ = fmt.Fprintf(w, "  %s %s\n",
		red(fmt.Sprintf("[L%d] ―", original.Line)),
		red(origVal),
	)
	_, _ = fmt.Fprintf(w, "  %s %s\n",
		green(fmt.Sprintf("[L%d] +", processed.Line)),
		green(procVal),
	)
}

// applyMask returns (possibly masked) value and whether masking occurred.
func applyMask(value string, debug bool, path string) (string, bool) {
	if strings.HasPrefix(value, AES) {
		return maskEncryptedValue(value, debug, path), true
	}
	if isSensitiveValue(value) {
		return MaskedValue, true
	}
	return value, false
}
