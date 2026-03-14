package channels

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

const (
	OutboundActionBlock  = "block"
	OutboundActionReview = "review"
)

type OutboundScanFinding struct {
	Category string `json:"category"`
	Path     string `json:"path"`
	Preview  string `json:"preview,omitempty"`
	Action   string `json:"action"`
}

type OutboundScanReport struct {
	Findings []OutboundScanFinding `json:"findings"`
}

func (r OutboundScanReport) FirstByAction(action string) (OutboundScanFinding, bool) {
	for _, finding := range r.Findings {
		if finding.Action == action {
			return finding, true
		}
	}
	return OutboundScanFinding{}, false
}

type OutboundScanner interface {
	Scan(ctx context.Context, job ChannelOutbox) (OutboundScanReport, error)
}

type OutboundReviewRequest struct {
	TenantID  uuid.UUID
	OutboxID  uuid.UUID
	Provider  string
	Recipient string
	Report    OutboundScanReport
}

type OutboundReviewSink interface {
	CreateReview(ctx context.Context, q database.Querier, request OutboundReviewRequest) error
}

type StructuredOutboundScanner struct {
	blockRules  []scanRule
	reviewRules []scanRule
}

type scanRule struct {
	category string
	pattern  *regexp.Regexp
	action   string
}

func NewStructuredOutboundScanner() *StructuredOutboundScanner {
	return &StructuredOutboundScanner{
		blockRules: []scanRule{
			{category: "secret_leak", pattern: regexp.MustCompile(`(?i)(sk_live_[a-z0-9]+|ghp_[a-z0-9]+|xox[baprs]-[a-z0-9-]+|AKIA[0-9A-Z]{16})`), action: OutboundActionBlock},
			{category: "malicious_payload", pattern: regexp.MustCompile(`(?i)(/dev/tcp/|base64\s+-d\s*\|\s*(sh|bash)|curl\s+[^|]+\|\s*(sh|bash))`), action: OutboundActionBlock},
		},
		reviewRules: []scanRule{
			{category: "pii", pattern: regexp.MustCompile(`\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b`), action: OutboundActionReview},
			{category: "pii", pattern: regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`), action: OutboundActionReview},
		},
	}
}

func (s *StructuredOutboundScanner) Scan(_ context.Context, job ChannelOutbox) (OutboundScanReport, error) {
	if s == nil || len(job.Payload) == 0 {
		return OutboundScanReport{}, nil
	}

	var payload any
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return OutboundScanReport{}, err
	}

	report := OutboundScanReport{}
	s.scanValue("payload", payload, &report.Findings)
	return report, nil
}

func (s *StructuredOutboundScanner) scanValue(path string, value any, findings *[]OutboundScanFinding) {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			s.scanValue(nextPath, nested, findings)
		}
	case []any:
		for _, nested := range typed {
			s.scanValue(path, nested, findings)
		}
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return
		}
		for _, rule := range s.blockRules {
			if match := rule.pattern.FindString(text); match != "" {
				*findings = append(*findings, OutboundScanFinding{
					Category: rule.category,
					Path:     path,
					Preview:  truncateFindingPreview(match),
					Action:   rule.action,
				})
			}
		}
		for _, rule := range s.reviewRules {
			if match := rule.pattern.FindString(text); match != "" {
				*findings = append(*findings, OutboundScanFinding{
					Category: rule.category,
					Path:     path,
					Preview:  truncateFindingPreview(match),
					Action:   rule.action,
				})
			}
		}
	}
}

func truncateFindingPreview(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 32 {
		return value
	}
	return value[:29] + "..."
}
