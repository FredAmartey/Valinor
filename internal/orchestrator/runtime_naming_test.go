package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDockerNamingConstantsUseHeimdall(t *testing.T) {
	assert.Equal(t, "heimdall.agent", dockerContainerLabel)
	assert.Equal(t, "heimdall.tenant", dockerTenantLabel)
}
