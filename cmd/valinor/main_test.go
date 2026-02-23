package main

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func TestBuildConnectorHandler(t *testing.T) {
	assert.Nil(t, buildConnectorHandler(nil))

	pool := (*database.Pool)(&pgxpool.Pool{})
	assert.NotNil(t, buildConnectorHandler(pool))
}
