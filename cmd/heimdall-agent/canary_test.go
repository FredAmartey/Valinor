package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckCanary_DetectsToken(t *testing.T) {
	agent := &Agent{
		canaryTokens: []string{"CANARY-abc123", "CANARY-def456"},
	}

	found, token := agent.checkCanary("The answer is 42")
	assert.False(t, found)
	assert.Empty(t, token)

	found, token = agent.checkCanary("Here is the info CANARY-abc123 you wanted")
	assert.True(t, found)
	assert.Equal(t, "CANARY-abc123", token)
}

func TestCheckCanary_EmptyTokens(t *testing.T) {
	agent := &Agent{}

	found, _ := agent.checkCanary("CANARY-abc123 anything")
	assert.False(t, found)
}
