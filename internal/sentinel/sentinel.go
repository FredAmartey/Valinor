package sentinel

import "context"

// ScanInput is the input to the sentinel scanner.
type ScanInput struct {
	TenantID string
	UserID   string
	Content  string // the user message content to scan
}

// ScanResult is the output of the sentinel scanner.
type ScanResult struct {
	Allowed    bool
	Score      float64 // 0.0 = safe, 1.0 = definite injection
	Reason     string  // e.g. "pattern:role_injection" or "llm:high_confidence"
	Quarantine bool    // allow but flag for review
}

// Sentinel scans user messages for prompt injection attacks.
type Sentinel interface {
	Scan(ctx context.Context, input ScanInput) (ScanResult, error)
}

// NopSentinel always allows messages (for testing / when sentinel is disabled).
type NopSentinel struct{}

func (NopSentinel) Scan(_ context.Context, _ ScanInput) (ScanResult, error) {
	return ScanResult{Allowed: true, Score: 0}, nil
}
