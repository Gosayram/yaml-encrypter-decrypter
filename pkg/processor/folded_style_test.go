package processor

import (
	"strings"
	"testing"

	"github.com/Gosayram/yaml-encrypter-decrypter/pkg/logger"
	"go.uber.org/zap"
)

func TestProtectFoldedStyleSections(t *testing.T) {
	testLogger := zap.NewExample()
	logger.ReplaceGlobals(testLogger)
	defer logger.ReplaceGlobals(logger.L())

	testLogger.Info("Starting TestProtectFoldedStyleSections")

	tests := []struct {
		name                string
		content             string
		expectedPlaceholder string
		expectedSections    int
	}{
		{
			name: "basic_folded_style",
			content: `key1: value1
key2: >-
  This is a folded
  style text that should
  be protected.
key3: value3`,
			expectedPlaceholder: `"FOLDED_STYLE_PLACEHOLDER_0"`,
			expectedSections:    1,
		},
		{
			name: "multiple_folded_sections",
			content: `key1: >-
  First folded
  section.
key2: value2
key3: >-
  Second folded
  section with
  more lines.
key4: value4`,
			expectedPlaceholder: `"FOLDED_STYLE_PLACEHOLDER_1"`,
			expectedSections:    2,
		},
		{
			name: "folded_section_at_end",
			content: `key1: value1
key2: value2
key3: >-
  Folded section
  at the end of file.`,
			expectedPlaceholder: `"FOLDED_STYLE_PLACEHOLDER_0"`,
			expectedSections:    1,
		},
		{
			name: "indented_folded_section",
			content: `root:
  key1: value1
  key2: >-
    This is an indented
    folded section.
  key3: value3`,
			expectedPlaceholder: `"FOLDED_STYLE_PLACEHOLDER_0"`,
			expectedSections:    1,
		},
		{
			name:             "no_folded_sections",
			content:          `key1: value1\nkey2: value2\nkey3: value3`,
			expectedSections: 0,
		},
		{
			name: "folded_style_without_dash",
			content: `key1: value1
key2: >
  Folded style without dash
  should also be protected.
key3: value3`,
			expectedPlaceholder: `"FOLDED_STYLE_PLACEHOLDER_0"`,
			expectedSections:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert \n to actual newlines
			content := strings.ReplaceAll(tt.content, "\\n", "\n")

			sections, processed := protectFoldedStyleSections([]byte(content), true)

			// Check if the number of sections found is as expected
			if len(sections) != tt.expectedSections {
				t.Errorf("Expected %d folded sections, got %d", tt.expectedSections, len(sections))
			}

			// If we expect sections, check if placeholder is present in the processed content
			if tt.expectedSections > 0 && !strings.Contains(string(processed), tt.expectedPlaceholder) {
				t.Errorf("Expected placeholder %s not found in processed content", tt.expectedPlaceholder)
			}

			// Check if sections have correct data
			for i, section := range sections {
				if section.Key == "" {
					t.Errorf("Section %d has empty key", i)
				}

				if section.Content == "" {
					t.Errorf("Section %d has empty content", i)
				}

				// The content should contain the key line and the folded content
				if !strings.Contains(section.Content, section.Key) {
					t.Errorf("Section %d content does not contain its key", i)
				}
			}
		})
	}
}

func TestRestoreFoldedStyleSections(t *testing.T) {
	tests := []struct {
		name             string
		processedContent string
		foldedSections   []FoldedStyleSection
		expectedContent  string
	}{
		{
			name: "restore_single_section",
			processedContent: `key1: value1
key2: "FOLDED_STYLE_PLACEHOLDER_0"
key3: value3`,
			foldedSections: []FoldedStyleSection{
				{
					Key:         "key2",
					IndentLevel: 0,
					Content:     "key2: >-\n  This is a folded\n  style text.\n",
				},
			},
			expectedContent: `key1: value1
key2: >-
  This is a folded
  style text.
key3: value3`,
		},
		{
			name: "restore_multiple_sections",
			processedContent: `key1: "FOLDED_STYLE_PLACEHOLDER_0"
key2: value2
key3: "FOLDED_STYLE_PLACEHOLDER_1"
key4: value4`,
			foldedSections: []FoldedStyleSection{
				{
					Key:         "key1",
					IndentLevel: 0,
					Content:     "key1: >-\n  First folded\n  section.\n",
				},
				{
					Key:         "key3",
					IndentLevel: 0,
					Content:     "key3: >-\n  Second folded\n  section.\n",
				},
			},
			expectedContent: `key1: >-
  First folded
  section.
key2: value2
key3: >-
  Second folded
  section.
key4: value4`,
		},
		{
			name: "restore_indented_section",
			processedContent: `root:
  key1: value1
  key2: "FOLDED_STYLE_PLACEHOLDER_0"
  key3: value3`,
			foldedSections: []FoldedStyleSection{
				{
					Key:         "key2",
					IndentLevel: 2,
					Content:     "  key2: >-\n    This is an indented\n    folded section.\n",
				},
			},
			expectedContent: `root:
  key1: value1
  key2: >-
    This is an indented
    folded section.
  key3: value3`,
		},
		{
			name:             "no_sections_to_restore",
			processedContent: "key1: value1\nkey2: value2\nkey3: value3",
			foldedSections:   []FoldedStyleSection{},
			expectedContent:  "key1: value1\nkey2: value2\nkey3: value3",
		},
		{
			name: "section_with_empty_content",
			processedContent: `key1: value1
key2: "FOLDED_STYLE_PLACEHOLDER_0"
key3: value3`,
			foldedSections: []FoldedStyleSection{
				{
					Key:         "key2",
					IndentLevel: 0,
					Content:     "key2: >-\n",
				},
			},
			expectedContent: `key1: value1
key2: >-
key3: value3`, // The implementation restores the folded style marker even with empty content
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert \n to actual newlines
			processedContent := strings.ReplaceAll(tt.processedContent, "\\n", "\n")
			expectedContent := strings.ReplaceAll(tt.expectedContent, "\\n", "\n")

			result := restoreFoldedStyleSections([]byte(processedContent), tt.foldedSections, true)

			// Compare results line by line to make debugging easier
			resultLines := strings.Split(string(result), "\n")
			expectedLines := strings.Split(expectedContent, "\n")

			if len(resultLines) != len(expectedLines) {
				t.Errorf("Line count mismatch: got %d lines, expected %d lines",
					len(resultLines), len(expectedLines))
				t.Errorf("Got:\n%s\nExpected:\n%s", string(result), expectedContent)
				return
			}

			for i, line := range resultLines {
				if line != expectedLines[i] {
					t.Errorf("Line %d mismatch\nGot:      '%s'\nExpected: '%s'",
						i+1, line, expectedLines[i])
				}
			}

			if string(result) != expectedContent {
				t.Errorf("Content mismatch\nGot:\n%s\nExpected:\n%s",
					string(result), expectedContent)
			}
		})
	}
}

func TestProtectAndRestoreFoldedStyleSections(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "full_cycle_single_section",
			content: `key1: value1
key2: >-
  This is a folded
  style text that should
  be protected and restored.
key3: value3`,
			expected: `key1: value1
key2: >-
  This is a folded
  style text that should
  be protected and restored.
key3: value3`,
		},
		{
			name: "full_cycle_multiple_sections",
			content: `key1: >-
  First folded
  section.
key2: value2
key3: >-
  Second folded
  section with
  more lines.
key4: value4`,
			expected: `key1: >-
  First folded
  section.
key2: value2
key3: >-
  Second folded
  section with
  more lines.
key4: value4`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert \n to actual newlines
			content := strings.ReplaceAll(tt.content, "\\n", "\n")
			expected := strings.ReplaceAll(tt.expected, "\\n", "\n")

			// Step 1: Protect folded sections
			sections, processed := protectFoldedStyleSections([]byte(content), true)

			// Debug print
			logger.L().Debug("Protected content",
				zap.Int("sections", len(sections)),
				zap.String("content", string(processed)))

			// Optional processing could happen here

			// Step 2: Restore folded sections
			result := restoreFoldedStyleSections(processed, sections, true)

			// Debug print
			logger.L().Debug("Restored content", zap.String("content", string(result)))

			// Compare results
			if string(result) != expected {
				t.Errorf("Content after full cycle doesn't match original\nGot:\n%s\nExpected:\n%s",
					string(result), expected)
			}
		})
	}
}
