package sentinel

import "context"

// Composite chains a PatternMatcher (fast, first) with an optional LLM classifier (slow, second).
type Composite struct {
	patterns *PatternMatcher
	llm      Sentinel // may be nil if LLM is disabled
}

// NewComposite creates a two-stage sentinel. Pass nil for llm to disable LLM classification.
func NewComposite(patterns *PatternMatcher, llm Sentinel) *Composite {
	return &Composite{patterns: patterns, llm: llm}
}

// Scan runs pattern matching first. If blocked, returns immediately. Otherwise calls LLM.
func (c *Composite) Scan(ctx context.Context, input ScanInput) (ScanResult, error) {
	result, err := c.patterns.Scan(ctx, input)
	if err != nil {
		return result, err
	}
	if !result.Allowed {
		return result, nil
	}

	if c.llm == nil {
		return result, nil
	}

	return c.llm.Scan(ctx, input)
}
