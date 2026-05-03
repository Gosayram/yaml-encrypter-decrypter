package processor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ProcessFile processes a YAML file with encryption or decryption
func ProcessFile(filePath, key, operation string, debug bool, configPath string) error {
	debugLog(debug, "Processing file: %s", filePath)

	safeKeyLog := "****"
	if len(key) > minKeyLengthToShow {
		safeKeyLog = "****" + key[len(key)-4:]
	}
	debugLog(debug, "Using key ending with: %s", safeKeyLog)

	if configPath != "" && !filepath.IsAbs(configPath) {
		absConfigPath, err := filepath.Abs(configPath)
		if err == nil {
			configPath = absConfigPath
			debugLog(debug, "Using absolute config path: %s", configPath)
		} else {
			debugLog(debug, "Failed to get absolute path for %s: %v", configPath, err)
		}
	}

	content, err := os.ReadFile(filePath) // #nosec G304 - file path is validated by caller
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Protect folded style sections before processing
	foldedSections, protectedContent := protectFoldedStyleSections(content, debug)

	rules, _, err := loadRules(configPath, debug)
	if err != nil {
		return fmt.Errorf("error loading rules: %w", err)
	}

	processedPaths := make(map[string]bool)

	node, err := processYAMLContent(protectedContent, key, operation, rules, processedPaths, debug)
	if err != nil {
		return fmt.Errorf("error processing YAML content: %w", err)
	}

	backupPath := filePath + ".bak"
	if err := os.WriteFile(backupPath, content, SecureFileMode); err != nil { // #nosec G703 - backup path is derived from validated input
		return fmt.Errorf("error creating backup file: %w", err)
	}

	processedContent, err := applyScalarEditsToOriginalContent(protectedContent, node)
	if err != nil {
		return fmt.Errorf("error applying scalar edits: %w", err)
	}

	// Restore folded style sections
	processedContent = restoreFoldedStyleSections(processedContent, foldedSections, debug)

	if err := os.WriteFile(filePath, processedContent, SecureFileMode); err != nil {
		return fmt.Errorf("error writing file: %w", err)
	}

	return nil
}

type scalarEdit struct {
	start       int
	end         int
	replacement string
}

func applyScalarEditsToOriginalContent(original []byte, processedNode *yaml.Node) ([]byte, error) {
	var parsedOriginal yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(original))
	if err := decoder.Decode(&parsedOriginal); err != nil {
		return nil, fmt.Errorf("error parsing original YAML: %w", err)
	}

	if processedNode == nil {
		return nil, errors.New("processed node is nil")
	}

	originalLines := strings.Split(string(original), "\n")
	lineOffsets := make([]int, len(originalLines))
	offset := 0
	for i, line := range originalLines {
		lineOffsets[i] = offset
		offset += len(line)
		if i < len(originalLines)-1 {
			offset++
		}
	}

	var edits []scalarEdit
	if err := collectScalarEdits(&parsedOriginal, processedNode, originalLines, lineOffsets, &edits); err != nil {
		return nil, err
	}

	if len(edits) == 0 {
		return original, nil
	}

	sort.Slice(edits, func(i, j int) bool {
		return edits[i].start > edits[j].start
	})

	updated := string(original)
	for _, edit := range edits {
		if edit.start < 0 || edit.end < edit.start || edit.end > len(updated) {
			return nil, fmt.Errorf("invalid edit range: [%d,%d)", edit.start, edit.end)
		}
		updated = updated[:edit.start] + edit.replacement + updated[edit.end:]
	}

	return []byte(updated), nil
}

func collectScalarEdits(originalNode, processedNode *yaml.Node, lines []string, lineOffsets []int, edits *[]scalarEdit) error {
	if originalNode == nil || processedNode == nil {
		return nil
	}

	if originalNode.Kind != processedNode.Kind {
		return nil
	}

	if originalNode.Kind == yaml.ScalarNode {
		if originalNode.Value == processedNode.Value &&
			originalNode.Style == processedNode.Style &&
			originalNode.Tag == processedNode.Tag {
			return nil
		}

		start, end, err := locateScalarSpan(originalNode, lines, lineOffsets)
		if err != nil {
			return err
		}

		replacement := renderScalarReplacement(originalNode, processedNode, lines)
		*edits = append(*edits, scalarEdit{
			start:       start,
			end:         end,
			replacement: replacement,
		})
		return nil
	}

	for i := 0; i < len(originalNode.Content) && i < len(processedNode.Content); i++ {
		if err := collectScalarEdits(originalNode.Content[i], processedNode.Content[i], lines, lineOffsets, edits); err != nil {
			return err
		}
	}

	return nil
}

func locateScalarSpan(node *yaml.Node, lines []string, lineOffsets []int) (int, int, error) {
	if node.Line <= 0 || node.Line > len(lines) {
		return 0, 0, fmt.Errorf("invalid node line: %d", node.Line)
	}

	lineIdx := node.Line - 1
	line := lines[lineIdx]
	startInLine := byteIndexAtColumn(line, node.Column)
	start := lineOffsets[lineIdx] + startInLine

	switch node.Style {
	case yaml.LiteralStyle, yaml.FoldedStyle:
		end := locateBlockScalarEnd(node, lines, lineOffsets)
		return start, end, nil
	default:
		endInLine := locateInlineScalarEnd(node, line, startInLine)
		end := lineOffsets[lineIdx] + endInLine
		return start, end, nil
	}
}

func locateBlockScalarEnd(node *yaml.Node, lines []string, lineOffsets []int) int {
	headerLine := node.Line - 1
	headerIndent := leadingSpaces(lines[headerLine])
	endLine := len(lines)

	for i := headerLine + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if leadingSpaces(line) <= headerIndent {
			endLine = i
			break
		}
	}

	if endLine >= len(lines) {
		return len(strings.Join(lines, "\n"))
	}
	return lineOffsets[endLine]
}

func locateInlineScalarEnd(node *yaml.Node, line string, start int) int {
	if start >= len(line) {
		return len(line)
	}

	switch node.Style {
	case yaml.DoubleQuotedStyle:
		return findDoubleQuotedEnd(line, start)
	case yaml.SingleQuotedStyle:
		return findSingleQuotedEnd(line, start)
	default:
		return findPlainScalarEnd(line, start)
	}
}

func findDoubleQuotedEnd(line string, start int) int {
	for i := start + 1; i < len(line); i++ {
		if line[i] == '"' && !isEscapedInDoubleQuoted(line, i) {
			return i + 1
		}
	}
	return len(line)
}

func isEscapedInDoubleQuoted(line string, quotePos int) bool {
	if quotePos <= 0 || quotePos >= len(line) {
		return false
	}

	backslashes := 0
	for i := quotePos - 1; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}

	return backslashes%2 == 1
}

func findSingleQuotedEnd(line string, start int) int {
	for i := start + 1; i < len(line); i++ {
		if line[i] != '\'' {
			continue
		}
		if i+1 < len(line) && line[i+1] == '\'' {
			i++
			continue
		}
		return i + 1
	}
	return len(line)
}

func findPlainScalarEnd(line string, start int) int {
	commentPos := -1
	for i := start; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			commentPos = i
			break
		}
	}
	if commentPos == -1 {
		return len(strings.TrimRight(line, " \t"))
	}
	j := commentPos - 1
	for j >= start && (line[j] == ' ' || line[j] == '\t') {
		j--
	}
	return j + 1
}

func renderScalarReplacement(originalNode, processedNode *yaml.Node, lines []string) string {
	originalStyle := originalNode.Style
	value := processedNode.Value

	if originalStyle == yaml.LiteralStyle || originalStyle == yaml.FoldedStyle {
		indicator := defaultBlockScalarIndicator(originalStyle)
		indicator = extractBlockScalarIndicator(originalNode, lines, indicator)
		trailingNewlines := countTrailingNewlines(value)

		headerLine := lines[originalNode.Line-1]
		contentIndent := strings.Repeat(" ", leadingSpaces(headerLine)+2+extractBlockScalarIndent(indicator))
		lines := strings.Split(strings.TrimRight(value, "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			return indicator
		}
		for i := range lines {
			lines[i] = contentIndent + lines[i]
		}
		return indicator + "\n" + strings.Join(lines, "\n") + blockScalarTerminator(indicator, trailingNewlines)
	}

	inlineStyle := processedNode.Style
	if originalStyle == yaml.DoubleQuotedStyle || originalStyle == yaml.SingleQuotedStyle {
		inlineStyle = originalStyle
	}
	return renderInlineScalar(value, inlineStyle)
}

func defaultBlockScalarIndicator(style yaml.Style) string {
	if style == yaml.FoldedStyle {
		return ">"
	}
	return "|"
}

func extractBlockScalarIndicator(node *yaml.Node, lines []string, fallback string) string {
	if node == nil || node.Line <= 0 || node.Line > len(lines) {
		return fallback
	}

	headerLine := lines[node.Line-1]
	start := byteIndexAtColumn(headerLine, node.Column)
	if start < 0 || start >= len(headerLine) {
		return fallback
	}

	if headerLine[start] != '|' && headerLine[start] != '>' {
		return fallback
	}

	end := start + 1
	for end < len(headerLine) {
		ch := headerLine[end]
		if (ch >= '0' && ch <= '9') || ch == '+' || ch == '-' {
			end++
			continue
		}
		break
	}

	indicator := headerLine[start:end]
	if indicator == "" {
		return fallback
	}
	return indicator
}

func extractBlockScalarIndent(indicator string) int {
	if len(indicator) <= 1 {
		return 0
	}

	numStr := indicator[1:]
	indent, err := strconv.Atoi(numStr)
	if err != nil {
		return 0
	}
	return indent
}

func countTrailingNewlines(value string) int {
	count := 0
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] != '\n' {
			break
		}
		count++
	}
	return count
}

func blockScalarTerminator(indicator string, trailingNewlines int) string {
	newlines := 1
	if strings.Contains(indicator, "+") && trailingNewlines > 0 {
		newlines = trailingNewlines
	}
	return strings.Repeat("\n", newlines)
}

func renderInlineScalar(value string, style yaml.Style) string {
	switch style {
	case yaml.DoubleQuotedStyle:
		return `"` + escapeDoubleQuoted(value) + `"`
	case yaml.SingleQuotedStyle:
		return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
	default:
		if needsQuoting(value) {
			return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
		}
		return value
	}
}

func escapeDoubleQuoted(value string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\t", `\t`,
		"\r", `\r`,
	)
	return replacer.Replace(value)
}

func needsQuoting(value string) bool {
	if value == "" {
		return true
	}
	if strings.ContainsAny(value, "\n\r\t") {
		return true
	}
	if strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
		return true
	}

	lower := strings.ToLower(value)
	if lower == "true" || lower == "false" || lower == "null" || value == "~" {
		return true
	}

	if isNumeric(value) {
		return true
	}

	if strings.ContainsAny(string(value[0]), "!&*%?|-<>@`\"'#") {
		return true
	}

	if strings.Contains(value, ": ") || strings.Contains(value, "#") || strings.ContainsAny(value, "[]{}, ") {
		return true
	}

	return false
}

func byteIndexAtColumn(line string, column int) int {
	if column <= 1 {
		return 0
	}
	idx := 0
	for currentCol := 1; currentCol < column && idx < len(line); currentCol++ {
		_, size := utf8.DecodeRuneInString(line[idx:])
		if size <= 0 {
			break
		}
		idx += size
	}
	return idx
}

func leadingSpaces(s string) int {
	count := 0
	for _, r := range s {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

// readYAMLWithBuffer reads YAML file with buffering
func readYAMLWithBuffer(filename string) (_ *yaml.Node, err error) {
	file, err := os.Open(filename) // #nosec G304 - file path is validated by caller
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	reader := bufio.NewReader(file)
	decoder := yaml.NewDecoder(reader)
	var data yaml.Node
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

// writeYAMLWithBuffer writes YAML file with buffering
func writeYAMLWithBuffer(filename string, data *yaml.Node) error {
	file, err := os.Create(filename) // #nosec G304 - file path is validated by caller
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(file)
	encoder := yaml.NewEncoder(writer)
	encoder.SetIndent(DefaultIndent)
	if err := encoder.Encode(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
