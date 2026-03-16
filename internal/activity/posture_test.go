package activity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildSecurityOverview(t *testing.T) {
	overview := buildSecurityOverview(SecurityOverviewConfig{
		WSAllowedOrigins:        []string{"app.heimdall.test"},
		WebSocketAuthEnabled:    true,
		EnabledChannelProviders: []string{"slack", "telegram"},
	}, securityOverviewStats{
		ProviderSecrets: map[string]providerSecretStatus{
			"slack": {
				HasAccessToken:   true,
				HasSigningSecret: true,
			},
			"telegram": {
				HasAccessToken: true,
			},
		},
		SharedRuntimeAgents: 0,
		BroadToolAgents:     0,
		UnhealthyAgents:     0,
	})

	assert.Len(t, overview.Checks, 5)
	assert.Equal(t, 5, overview.Healthy)
	assert.Equal(t, 0, overview.Warning)
	assert.Equal(t, 0, overview.Critical)
}

func TestBuildSecurityOverview_FlagsWarnings(t *testing.T) {
	overview := buildSecurityOverview(SecurityOverviewConfig{
		WSAllowedOrigins:        nil,
		WebSocketAuthEnabled:    false,
		EnabledChannelProviders: []string{"slack", "whatsapp"},
	}, securityOverviewStats{
		ProviderSecrets: map[string]providerSecretStatus{
			"slack": {
				HasAccessToken: true,
			},
		},
		SharedRuntimeAgents: 2,
		BroadToolAgents:     1,
		UnhealthyAgents:     3,
	})

	assert.Equal(t, 0, overview.Healthy)
	assert.Equal(t, 4, overview.Warning)
	assert.Equal(t, 1, overview.Critical)
	assert.Equal(t, "critical", overview.Checks[0].Status)
}
