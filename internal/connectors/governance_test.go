package connectors

import (
	"encoding/json"
	"testing"

	"github.com/FredAmartey/heimdall/internal/activity"
	"github.com/FredAmartey/heimdall/internal/policies"
	"github.com/stretchr/testify/assert"
)

func TestEvaluateGovernanceDecision(t *testing.T) {
	tool := ConnectorTool{
		Name:       "salesforce.update_contact",
		ActionType: "write",
		RiskClass:  activity.RiskClassExternalWrites,
	}

	t.Run("allow", func(t *testing.T) {
		result, err := EvaluateGovernance(tool, policies.PolicySet{
			activity.RiskClassExternalWrites: policies.DecisionAllow,
		}, nil)
		assert.NoError(t, err)
		assert.True(t, result.Governed)
		assert.Equal(t, policies.DecisionAllow, result.Decision)
	})

	t.Run("block", func(t *testing.T) {
		result, err := EvaluateGovernance(tool, policies.PolicySet{
			activity.RiskClassExternalWrites: policies.DecisionBlock,
		}, nil)
		assert.NoError(t, err)
		assert.True(t, result.Governed)
		assert.Equal(t, policies.DecisionBlock, result.Decision)
	})

	t.Run("require approval", func(t *testing.T) {
		result, err := EvaluateGovernance(tool, policies.PolicySet{
			activity.RiskClassExternalWrites: policies.DecisionRequireApproval,
		}, nil)
		assert.NoError(t, err)
		assert.True(t, result.Governed)
		assert.Equal(t, policies.DecisionRequireApproval, result.Decision)
	})

	t.Run("agent override beats tenant default", func(t *testing.T) {
		result, err := EvaluateGovernance(
			tool,
			policies.PolicySet{activity.RiskClassExternalWrites: policies.DecisionRequireApproval},
			policies.PolicySet{activity.RiskClassExternalWrites: policies.DecisionAllow},
		)
		assert.NoError(t, err)
		assert.Equal(t, policies.DecisionAllow, result.Decision)
	})

	t.Run("missing metadata fails closed", func(t *testing.T) {
		result, err := EvaluateGovernance(ConnectorTool{
			Name:       "salesforce.update_contact",
			ActionType: "write",
		}, policies.DefaultPolicySet(), nil)
		assert.ErrorIs(t, err, ErrConnectorToolRiskClassNeeded)
		assert.True(t, result.Governed)
		assert.Equal(t, policies.DecisionBlock, result.Decision)
	})
}

func TestResolveGovernedTool(t *testing.T) {
	raw := json.RawMessage(`[
		{"name":"salesforce.read_contact"},
		{"name":"salesforce.update_contact","action_type":"write","risk_class":"external_writes"}
	]`)

	tool, err := ResolveToolDefinition(raw, "salesforce.update_contact")
	assert.NoError(t, err)
	assert.Equal(t, "salesforce.update_contact", tool.Name)
	assert.Equal(t, "write", tool.ActionType)

	_, err = ResolveToolDefinition(raw, "unknown.tool")
	assert.ErrorIs(t, err, ErrNotFound)
}
