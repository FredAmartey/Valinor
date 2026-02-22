package proxy_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestPushConfig_Success(t *testing.T) {
	transport := proxy.NewTCPTransport(9850)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	ctx := context.Background()
	cid := uint32(3)

	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	// Mock agent that acks config
	var receivedFrame proxy.Frame
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		receivedFrame, err = ac.Recv(ctx)
		if err != nil {
			return
		}

		ack := proxy.Frame{
			Type:    proxy.TypeConfigAck,
			ID:      receivedFrame.ID,
			Payload: json.RawMessage(`{"applied":true}`),
		}
		_ = ac.Send(ctx, ack)
	}()

	config := map[string]any{"model": "gpt-4o"}
	allowlist := []string{"search_players", "get_report"}

	err = proxy.PushConfig(ctx, pool, "agent-1", cid, config, allowlist, nil, nil, 5*time.Second)
	require.NoError(t, err)

	<-done
	assert.Equal(t, proxy.TypeConfigUpdate, receivedFrame.Type)

	// Verify payload contains config and tool_allowlist
	var payload struct {
		Config        map[string]any `json:"config"`
		ToolAllowlist []string       `json:"tool_allowlist"`
	}
	err = json.Unmarshal(receivedFrame.Payload, &payload)
	require.NoError(t, err)
	assert.Equal(t, "gpt-4o", payload.Config["model"])
	assert.Equal(t, []string{"search_players", "get_report"}, payload.ToolAllowlist)
}

func TestPushConfig_NoListener(t *testing.T) {
	transport := proxy.NewTCPTransport(9860)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	err := proxy.PushConfig(context.Background(), pool, "agent-bad", 99, nil, nil, nil, nil, 2*time.Second)
	assert.Error(t, err)
}

func TestPushConfig_Timeout(t *testing.T) {
	transport := proxy.NewTCPTransport(9870)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	ctx := context.Background()
	cid := uint32(3)

	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	// Mock agent that accepts but never responds
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		// Read but don't reply — let it timeout
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		// Hold connection open
		<-ctx.Done()
		conn.Close()
	}()

	err = proxy.PushConfig(ctx, pool, "agent-1", cid, nil, nil, nil, nil, 500*time.Millisecond)
	assert.Error(t, err)
}
