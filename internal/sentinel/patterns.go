package sentinel

import (
	"context"
	"regexp"
	"strings"
)

// Pattern is a named regex pattern for detecting prompt injection.
type Pattern struct {
	Name   string
	Regexp *regexp.Regexp
}

// PatternMatcher scans messages against a list of regex patterns.
type PatternMatcher struct {
	patterns []Pattern
}

// NewPatternMatcher creates a PatternMatcher from compiled patterns.
func NewPatternMatcher(patterns []Pattern) *PatternMatcher {
	return &PatternMatcher{patterns: patterns}
}

// DefaultPatterns returns the built-in prompt injection detection patterns.
func DefaultPatterns() []Pattern {
	raw := []struct {
		name    string
		pattern string
	}{
		{"ignore_instructions", `(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)`},
		{"system_prompt_extract", `(?i)(repeat|show|print|reveal|output)\s+(your\s+)?(system\s+prompt|instructions|rules)`},
		{"role_injection", `(?i)\[\[?\s*system\s*\]?\]`},
		{"jailbreak_dan", `(?i)you\s+are\s+now\s+DAN`},
		{"prompt_override", `(?i)(disregard|forget|override)\s+(all\s+)?(previous|prior|above|your)\s+(instructions|rules|guidelines)`},
		{"act_as_bypass", `(?i)act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored)`},
	}

	patterns := make([]Pattern, 0, len(raw))
	for _, r := range raw {
		patterns = append(patterns, Pattern{
			Name:   r.name,
			Regexp: regexp.MustCompile(r.pattern),
		})
	}
	return patterns
}

// Scan checks the input against all patterns.
func (pm *PatternMatcher) Scan(_ context.Context, input ScanInput) (ScanResult, error) {
	content := strings.TrimSpace(input.Content)
	for _, p := range pm.patterns {
		if p.Regexp.MatchString(content) {
			return ScanResult{
				Allowed: false,
				Score:   1.0,
				Reason:  "pattern:" + p.Name,
			}, nil
		}
	}
	return ScanResult{Allowed: true, Score: 0}, nil
}
