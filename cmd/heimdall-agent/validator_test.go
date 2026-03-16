package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateToolCall_AllowedParams(t *testing.T) {
	agent := &Agent{
		toolAllowlist: []string{"search_players"},
		toolPolicies: map[string]ToolPolicy{
			"search_players": {
				AllowedParams: []string{"league", "position", "age_max"},
				DeniedParams:  []string{"salary", "contract_value"},
			},
		},
	}

	// Allowed tool with allowed params
	result := agent.validateToolCall("search_players", `{"league":"Serie A","position":"CB"}`)
	assert.True(t, result.Allowed)

	// Allowed tool with denied param
	result = agent.validateToolCall("search_players", `{"league":"Serie A","salary":1000000}`)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "salary")

	// Tool not in allow-list
	result = agent.validateToolCall("delete_all", `{}`)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "not in allow-list")
}

func TestValidateToolCall_NoPolicyAllowsAll(t *testing.T) {
	agent := &Agent{
		toolAllowlist: []string{"search_players"},
		toolPolicies:  nil,
	}

	result := agent.validateToolCall("search_players", `{"anything":"goes"}`)
	assert.True(t, result.Allowed)
}

func TestValidateToolCall_EmptyAllowlist(t *testing.T) {
	agent := &Agent{}

	result := agent.validateToolCall("anything", `{}`)
	assert.True(t, result.Allowed)
}
