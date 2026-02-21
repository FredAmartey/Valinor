package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
}

func TestLoad_EnvOverrides(t *testing.T) {
	os.Setenv("VALINOR_SERVER_PORT", "9090")
	os.Setenv("VALINOR_DATABASE_URL", "postgres://test:test@localhost:5432/valinor_test")
	defer func() {
		os.Unsetenv("VALINOR_SERVER_PORT")
		os.Unsetenv("VALINOR_DATABASE_URL")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "postgres://test:test@localhost:5432/valinor_test", cfg.Database.URL)
}
