package activity

import (
	"context"
	"fmt"
	"strings"

	"github.com/valinor-ai/valinor/internal/platform/database"
)

type SecurityOverviewConfig struct {
	WSAllowedOrigins        []string
	WebSocketAuthEnabled    bool
	EnabledChannelProviders []string
}

type SecurityOverview struct {
	Checks   []SecurityCheck `json:"checks"`
	Healthy  int             `json:"healthy"`
	Warning  int             `json:"warning"`
	Critical int             `json:"critical"`
}

type SecurityCheck struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Status   string         `json:"status"`
	Summary  string         `json:"summary"`
	Details  string         `json:"details,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type securityOverviewStats struct {
	ProviderSecrets     map[string]providerSecretStatus
	SharedRuntimeAgents int
	BroadToolAgents     int
	UnhealthyAgents     int
}

type providerSecretStatus struct {
	HasAccessToken   bool
	HasSigningSecret bool
	HasSecretToken   bool
}

func buildSecurityOverview(cfg SecurityOverviewConfig, stats securityOverviewStats) SecurityOverview {
	checks := []SecurityCheck{
		{
			ID:      "websocket-auth",
			Title:   "WebSocket authentication",
			Status:  map[bool]string{true: "healthy", false: "critical"}[cfg.WebSocketAuthEnabled],
			Summary: map[bool]string{true: "Interactive sessions require JWT auth before agents can be reached.", false: "Interactive sessions are not protected by JWT auth."}[cfg.WebSocketAuthEnabled],
		},
		{
			ID:      "origin-restrictions",
			Title:   "Origin restrictions",
			Status:  map[bool]string{true: "healthy", false: "warning"}[len(cfg.WSAllowedOrigins) > 0],
			Summary: map[bool]string{true: fmt.Sprintf("%d allowed origin pattern(s) protect browser upgrades.", len(cfg.WSAllowedOrigins)), false: "Browser-origin restrictions are not configured for agent WebSocket upgrades."}[len(cfg.WSAllowedOrigins) > 0],
		},
		buildChannelSecretCheck(cfg.EnabledChannelProviders, stats.ProviderSecrets),
		buildRuntimeBoundaryCheck(stats),
		buildToolScopeCheck(stats.BroadToolAgents),
	}

	overview := SecurityOverview{Checks: checks}
	for _, check := range checks {
		switch check.Status {
		case "healthy":
			overview.Healthy++
		case "critical":
			overview.Critical++
		default:
			overview.Warning++
		}
	}
	return overview
}

func buildChannelSecretCheck(enabledProviders []string, providers map[string]providerSecretStatus) SecurityCheck {
	if len(enabledProviders) == 0 {
		return SecurityCheck{
			ID:      "channel-secrets",
			Title:   "Channel secrets",
			Status:  "healthy",
			Summary: "No outbound channel providers are enabled for this environment.",
		}
	}

	var missing []string
	for _, provider := range enabledProviders {
		status, ok := providers[provider]
		if !ok {
			missing = append(missing, provider)
			continue
		}
		switch provider {
		case "slack":
			if !status.HasAccessToken || !status.HasSigningSecret {
				missing = append(missing, provider)
			}
		case "telegram":
			if !status.HasAccessToken {
				missing = append(missing, provider)
			}
		case "whatsapp":
			if !status.HasAccessToken || !status.HasSecretToken {
				missing = append(missing, provider)
			}
		default:
			if !status.HasAccessToken {
				missing = append(missing, provider)
			}
		}
	}

	if len(missing) == 0 {
		return SecurityCheck{
			ID:      "channel-secrets",
			Title:   "Channel secrets",
			Status:  "healthy",
			Summary: "Enabled channel providers have tenant-scoped secrets configured.",
		}
	}

	return SecurityCheck{
		ID:      "channel-secrets",
		Title:   "Channel secrets",
		Status:  "warning",
		Summary: "Some enabled channel providers are missing tenant-scoped secrets.",
		Details: "Missing coverage: " + strings.Join(missing, ", "),
	}
}

func buildRuntimeBoundaryCheck(stats securityOverviewStats) SecurityCheck {
	if stats.SharedRuntimeAgents == 0 && stats.UnhealthyAgents == 0 {
		return SecurityCheck{
			ID:      "runtime-boundaries",
			Title:   "Runtime boundaries",
			Status:  "healthy",
			Summary: "Running agents are user-affine and currently reporting healthy state.",
		}
	}

	parts := make([]string, 0, 2)
	if stats.SharedRuntimeAgents > 0 {
		parts = append(parts, fmt.Sprintf("%d shared runtime agent(s)", stats.SharedRuntimeAgents))
	}
	if stats.UnhealthyAgents > 0 {
		parts = append(parts, fmt.Sprintf("%d unhealthy/stale agent(s)", stats.UnhealthyAgents))
	}

	return SecurityCheck{
		ID:      "runtime-boundaries",
		Title:   "Runtime boundaries",
		Status:  "warning",
		Summary: "Isolation or runtime health needs attention.",
		Details: strings.Join(parts, "; "),
	}
}

func buildToolScopeCheck(broadToolAgents int) SecurityCheck {
	if broadToolAgents == 0 {
		return SecurityCheck{
			ID:      "tool-scope",
			Title:   "Tool scope",
			Status:  "healthy",
			Summary: "Active agents have explicit tool boundaries.",
		}
	}

	return SecurityCheck{
		ID:      "tool-scope",
		Title:   "Tool scope",
		Status:  "warning",
		Summary: "Some agents have empty or wildcard tool allowlists.",
		Details: fmt.Sprintf("%d agent(s) should be tightened before broader rollout.", broadToolAgents),
	}
}

func loadSecurityOverviewStats(ctx context.Context, q database.Querier, cfg SecurityOverviewConfig) (securityOverviewStats, error) {
	stats := securityOverviewStats{
		ProviderSecrets: make(map[string]providerSecretStatus),
	}

	if err := q.QueryRow(ctx,
		`SELECT
		    COUNT(*) FILTER (WHERE user_id IS NULL) AS shared_runtime_agents,
		    COUNT(*) FILTER (
		      WHERE (
		        jsonb_typeof(tool_allowlist) = 'array'
		        AND (
		          jsonb_array_length(tool_allowlist) = 0
		          OR tool_allowlist @> '["*"]'::jsonb
		        )
		      )
		    ) AS broad_tool_agents,
		    COUNT(*) FILTER (
		      WHERE status = 'unhealthy'
		    ) AS unhealthy_agents
		   FROM agent_instances
		  WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		    AND status != 'destroyed'`,
	).Scan(&stats.SharedRuntimeAgents, &stats.BroadToolAgents, &stats.UnhealthyAgents); err != nil {
		return stats, fmt.Errorf("loading agent posture stats: %w", err)
	}

	if len(cfg.EnabledChannelProviders) == 0 {
		return stats, nil
	}

	rows, err := q.Query(ctx,
		`SELECT provider,
		        NULLIF(BTRIM(access_token), '') IS NOT NULL AS has_access_token,
		        NULLIF(BTRIM(signing_secret), '') IS NOT NULL AS has_signing_secret,
		        NULLIF(BTRIM(secret_token), '') IS NOT NULL AS has_secret_token
		   FROM channel_provider_credentials
		  WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID`,
	)
	if err != nil {
		return stats, fmt.Errorf("loading provider secret posture: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			provider string
			status   providerSecretStatus
		)
		if err := rows.Scan(&provider, &status.HasAccessToken, &status.HasSigningSecret, &status.HasSecretToken); err != nil {
			return stats, fmt.Errorf("scanning provider secret posture: %w", err)
		}
		stats.ProviderSecrets[strings.ToLower(strings.TrimSpace(provider))] = status
	}
	if err := rows.Err(); err != nil {
		return stats, fmt.Errorf("iterating provider secret posture: %w", err)
	}

	return stats, nil
}
