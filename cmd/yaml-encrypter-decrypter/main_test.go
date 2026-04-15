package main

import (
	"reflect"
	"testing"
)

func TestParseIncludeRulePatterns(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "spaces only",
			input: "   ",
			want:  nil,
		},
		{
			name:  "separators only",
			input: ", , ,",
			want:  nil,
		},
		{
			name:  "single pattern",
			input: "rules.yml",
			want:  []string{"rules.yml"},
		},
		{
			name:  "multiple patterns with spaces and empties",
			input: "rules.yml, ./more.yml, , ../custom.yaml  ,",
			want:  []string{"rules.yml", "./more.yml", "../custom.yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIncludeRulePatterns(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseIncludeRulePatterns() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRequiredIncludeRulePatterns(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []string
		wantError bool
	}{
		{
			name:      "empty input returns error",
			input:     "",
			wantError: true,
		},
		{
			name:      "separators only returns error",
			input:     ", , ,",
			wantError: true,
		},
		{
			name:      "valid patterns",
			input:     "rules.yml, ./extra.yml",
			want:      []string{"rules.yml", "./extra.yml"},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRequiredIncludeRulePatterns(tt.input)
			if (err != nil) != tt.wantError {
				t.Fatalf("parseRequiredIncludeRulePatterns() error = %v, wantError %v", err, tt.wantError)
			}
			if !tt.wantError && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseRequiredIncludeRulePatterns() = %v, want %v", got, tt.want)
			}
		})
	}
}
