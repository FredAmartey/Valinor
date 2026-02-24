package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforceOpenClawRuntimePolicy_InsertsSecureDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := enforceOpenClawRuntimePolicy(map[string]any{
		"model": "gpt-4o",
	})
	require.NoError(t, err)

	assert.Equal(t, "gpt-4o", cfg["model"])
	assert.Equal(t, "non-main", nestedString(cfg, "agents", "defaults", "sandbox", "mode"))
	assert.Equal(t, true, nestedBool(cfg, "tools", "exec", "workspaceOnly"))
	assert.Equal(t, true, nestedBool(cfg, "tools", "exec", "applyPatch", "workspaceOnly"))
	assert.Equal(t, "loopback", nestedString(cfg, "gateway", "bind"))
}

func TestEnforceOpenClawRuntimePolicy_RejectsInsecureSandboxMode(t *testing.T) {
	t.Parallel()

	_, err := enforceOpenClawRuntimePolicy(map[string]any{
		"agents": map[string]any{
			"defaults": map[string]any{
				"sandbox": map[string]any{
					"mode": "off",
				},
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sandbox.mode")
}

func TestEnforceOpenClawRuntimePolicy_RejectsWorkspaceFlagsDisabled(t *testing.T) {
	t.Parallel()

	_, err := enforceOpenClawRuntimePolicy(map[string]any{
		"tools": map[string]any{
			"exec": map[string]any{
				"workspaceOnly": false,
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tools.exec.workspaceOnly")

	_, err = enforceOpenClawRuntimePolicy(map[string]any{
		"tools": map[string]any{
			"exec": map[string]any{
				"applyPatch": map[string]any{
					"workspaceOnly": false,
				},
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tools.exec.applyPatch.workspaceOnly")
}

func TestEnforceOpenClawRuntimePolicy_RejectsNonLoopbackGatewayBind(t *testing.T) {
	t.Parallel()

	_, err := enforceOpenClawRuntimePolicy(map[string]any{
		"gateway": map[string]any{
			"bind": "0.0.0.0",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway.bind")
}

func nestedString(root map[string]any, path ...string) string {
	val, _ := nestedLookup(root, path...)
	s, _ := val.(string)
	return s
}

func nestedBool(root map[string]any, path ...string) bool {
	val, _ := nestedLookup(root, path...)
	b, _ := val.(bool)
	return b
}

func nestedLookup(root map[string]any, path ...string) (any, bool) {
	var cur any = root
	for _, part := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := m[part]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}
