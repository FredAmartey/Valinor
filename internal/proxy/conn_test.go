package proxy_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestAgentConn_SendRecv(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	sConn := proxy.NewAgentConn(server)
	cConn := proxy.NewAgentConn(client)

	ctx := context.Background()

	// Send from client
	sent := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "req-1",
		Payload: json.RawMessage(`{"role":"user","content":"hello"}`),
	}

	errCh := make(chan error, 1)
	go func() { errCh <- cConn.Send(ctx, sent) }()

	// Receive on server
	received, err := sConn.Recv(ctx)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
	assert.Equal(t, sent.Type, received.Type)
	assert.Equal(t, sent.ID, received.ID)
}

func TestAgentConn_RoundTrip(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	sConn := proxy.NewAgentConn(server)
	cConn := proxy.NewAgentConn(client)

	ctx := context.Background()

	// Client sends message, server replies with chunks
	go func() {
		frame, err := sConn.Recv(ctx)
		if err != nil {
			return
		}
		// Echo back as chunk
		reply := proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"world","done":true}`),
		}
		_ = sConn.Send(ctx, reply)
	}()

	msg := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "req-2",
		Payload: json.RawMessage(`{"role":"user","content":"hello"}`),
	}
	err := cConn.Send(ctx, msg)
	require.NoError(t, err)

	reply, err := cConn.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeChunk, reply.Type)
	assert.Equal(t, "req-2", reply.ID)
}

func TestAgentConn_RecvClosedConn(t *testing.T) {
	server, client := net.Pipe()
	client.Close()

	sConn := proxy.NewAgentConn(server)
	_, err := sConn.Recv(context.Background())
	assert.Error(t, err)

	server.Close()
}
