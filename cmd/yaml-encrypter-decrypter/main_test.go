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
