package processor

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// cleanMultilineEncrypted cleans up a multiline encrypted string
func cleanMultilineEncrypted(encrypted string, debug bool) string {
	if !strings.Contains(encrypted, "\n") {
		return encrypted
	}

	debugLog(debug, "Detected multiline encrypted string, cleaning up...")
	// Remove all line breaks, spaces and other invisible characters
	cleanedEncrypted := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return -1 // Remove character
		}
		return r
	}, encrypted)

	debugLog(debug, "Cleaned encrypted string length: %d", len(cleanedEncrypted))
	return cleanedEncrypted
}

// extractStyleSuffix extracts style suffix from encrypted string
func extractStyleSuffix(encrypted string, debug bool) (string, string) {
	// Find and extract style suffix if present
	styleSuffix := ""
	resultString := encrypted

	styles := []string{StyleLiteral, StyleFolded, StyleDoubleQuoted, StyleSingleQuoted, StylePlain}
	for _, style := range styles {
		suffix := "|" + style
		if strings.HasSuffix(resultString, suffix) {
			styleSuffix = suffix
			resultString = resultString[:len(resultString)-len(suffix)]
			debugLog(debug, "Found style suffix: %s", styleSuffix)
			break
		}
	}

	return resultString, styleSuffix
}

// fixBase64Padding uses Base64 padding correction
func fixBase64Padding(encrypted string, debug bool) string {
	debugLog(debug, "Trying to fix Base64 string...")

	if encrypted == "" {
		return encrypted
	}

	debugLog(debug, "Input string: '%s', length: %d", encrypted, len(encrypted))

	cleanedEncrypted := strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, encrypted)

	trimmed := strings.TrimRight(cleanedEncrypted, "=")
	remainder := len(trimmed) % Base64BlockSize
	var paddedEncrypted string

	switch remainder {
	case Base64NoPadding:
		paddedEncrypted = trimmed
	case Base64InvalidPad:
		paddedEncrypted = trimmed + "==="
	case Base64DoublePadding:
		paddedEncrypted = trimmed + "=="
	case Base64SinglePadding:
		paddedEncrypted = trimmed + "="
	}

	debugLog(debug, "Padded string: '%s', length: %d", paddedEncrypted, len(paddedEncrypted))
	return paddedEncrypted
}

// applyNodeStyle applies a style to a scalar node
func applyNodeStyle(node *yaml.Node, styleInfo yaml.Style, debug bool) {
	if styleInfo != 0 {
		node.Style = styleInfo
		debugLog(debug, "Applied style from suffix to style: %d", styleInfo)
	} else if strings.Contains(node.Value, "\n") {
		node.Style = yaml.LiteralStyle
		debugLog(debug, "Applied literal style for multiline content")
	}
}

func styleSuffixToYAMLStyle(styleSuffix string) yaml.Style {
	switch styleSuffix {
	case "|" + StyleLiteral:
		return yaml.LiteralStyle
	case "|" + StyleFolded:
		return yaml.FoldedStyle
	case "|" + StyleDoubleQuoted:
		return yaml.DoubleQuotedStyle
	case "|" + StyleSingleQuoted:
		return yaml.SingleQuotedStyle
	default:
		return 0
	}
}

// getStyleSuffix returns the style suffix for a given style
func getStyleSuffix(style yaml.Style) string {
	switch style {
	case yaml.LiteralStyle:
		return "|" + StyleLiteral
	case yaml.FoldedStyle:
		return "|" + StyleFolded
	case yaml.DoubleQuotedStyle:
		return "|" + StyleDoubleQuoted
	case yaml.SingleQuotedStyle:
		return "|" + StyleSingleQuoted
	default:
		return "|" + StylePlain
	}
}

// GetStyleName returns the name of a style
func GetStyleName(style yaml.Style) string {
	switch style {
	case yaml.LiteralStyle:
		return StyleLiteral
	case yaml.FoldedStyle:
		return StyleFolded
	case yaml.DoubleQuotedStyle:
		return StyleDoubleQuoted
	case yaml.SingleQuotedStyle:
		return StyleSingleQuoted
	default:
		return StylePlain
	}
}

// protectFoldedStyleSections scans the YAML file for folded style sections and replaces them with placeholders.
func protectFoldedStyleSections(content []byte, debug bool) ([]FoldedStyleSection, []byte) {
	lines := strings.Split(string(content), "\n")
	var foldedSections []FoldedStyleSection
	var newLines []string

	inFoldedSection := false
	var currentSection FoldedStyleSection
	var currentIndent int

	lineRegex := regexp.MustCompile(`^(\s*)([^:]+):\s*>-?\s*$`)

	for i, line := range lines {
		if !inFoldedSection {
			matches := lineRegex.FindStringSubmatch(line)
			if len(matches) > 0 {
				indent := len(matches[1])
				key := matches[2]
				inFoldedSection = true
				currentSection = FoldedStyleSection{
					Key:         key,
					IndentLevel: indent,
					Content:     line + "\n",
				}
				currentIndent = indent + YAMLIndentSpaces

				newLines = append(newLines, fmt.Sprintf("%s%s: \"FOLDED_STYLE_PLACEHOLDER_%d\"", matches[1], key, len(foldedSections)))
				debugLog(debug, "Found folded style section for key: %s at line %d", key, i+1)
				continue
			}
		} else {
			if len(line) == 0 || strings.HasPrefix(line, strings.Repeat(" ", currentIndent)) {
				currentSection.Content += line + "\n"
				continue
			} else {
				inFoldedSection = false
				foldedSections = append(foldedSections, currentSection)
				debugLog(debug, "Completed folded style section: %s", currentSection.Key)
			}
		}
		newLines = append(newLines, line)
	}

	if inFoldedSection {
		foldedSections = append(foldedSections, currentSection)
		debugLog(debug, "Completed folded style section at end of file: %s", currentSection.Key)
	}

	return foldedSections, []byte(strings.Join(newLines, "\n"))
}

// restoreFoldedStyleSections restores the original folded style sections in the processed YAML content.
func restoreFoldedStyleSections(processedContent []byte, foldedSections []FoldedStyleSection, debug bool) []byte {
	content := string(processedContent)

	for i, section := range foldedSections {
		placeholder := fmt.Sprintf("\"FOLDED_STYLE_PLACEHOLDER_%d\"", i)
		debugLog(debug, "Restoring folded style section: %s", section.Key)

		contentLines := strings.Split(section.Content, "\n")
		if len(contentLines) > 1 {
			sectionContent := strings.Join(contentLines[1:], "\n")
			keyLine := fmt.Sprintf("%s%s: >-", strings.Repeat(" ", section.IndentLevel), section.Key)

			replacement := keyLine + "\n" + sectionContent
			content = strings.Replace(content, placeholder, "", 1)

			pattern := fmt.Sprintf("(%s%s:)[^\n]*\n", strings.Repeat(" ", section.IndentLevel), regexp.QuoteMeta(section.Key))
			re := regexp.MustCompile(pattern)
			content = re.ReplaceAllString(content, replacement)
		}
	}

	return []byte(content)
}

func isMultilineStyleNode(node *yaml.Node) bool {
	return node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle
}
