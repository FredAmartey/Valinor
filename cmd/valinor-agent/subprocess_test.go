package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSubprocess_StartStop(t *testing.T) {
	sp := &Subprocess{
		Name: "sleep",
		Args: []string{"30"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := sp.Start(ctx)
	require.NoError(t, err)
	require.True(t, sp.Running())

	err = sp.Stop(ctx)
	require.NoError(t, err)

	// Stop() now waits for the process to exit, so Running() is immediately false.
	require.False(t, sp.Running())
}

func TestSubprocess_WaitForReady_Timeout(t *testing.T) {
	sp := &Subprocess{
		Name:      "sleep",
		Args:      []string{"30"},
		ReadyURL:  "http://127.0.0.1:19999/nonexistent",
		ReadyWait: 500 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := sp.Start(ctx)
	require.NoError(t, err)

	// WaitForReady should fail since nothing listens on that port
	err = sp.WaitForReady(ctx)
	require.Error(t, err)

	_ = sp.Stop(ctx)
}

func TestSubprocess_WaitForReady_NoURL(t *testing.T) {
	sp := &Subprocess{
		Name: "sleep",
		Args: []string{"30"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := sp.Start(ctx)
	require.NoError(t, err)

	// WaitForReady with no URL should succeed immediately
	err = sp.WaitForReady(ctx)
	require.NoError(t, err)

	_ = sp.Stop(ctx)
}

func TestSubprocess_StopIdempotent(t *testing.T) {
	sp := &Subprocess{
		Name: "sleep",
		Args: []string{"30"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, sp.Start(ctx))
	require.NoError(t, sp.Stop(ctx))
	// Second stop should be a no-op
	require.NoError(t, sp.Stop(ctx))
}
