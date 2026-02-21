package telemetry_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/telemetry"
)

func TestNewLogger_JSON(t *testing.T) {
	var buf bytes.Buffer
	logger := telemetry.NewLogger("info", "json", &buf)

	logger.Info("test message", "key", "value")

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	assert.Equal(t, "test message", entry["msg"])
	assert.Equal(t, "value", entry["key"])
	assert.Equal(t, "INFO", entry["level"])
}

func TestNewLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := telemetry.NewLogger("warn", "json", &buf)

	logger.Info("should not appear")

	assert.Empty(t, buf.String())
}
