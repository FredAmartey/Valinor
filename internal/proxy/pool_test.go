package proxy_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestConnPool_GetCreatesConnection(t *testing.T) {
	transport := proxy.NewTCPTransport(9400)
	pool := proxy.NewConnPool(transport)
	ctx := context.Background()

	// Start a mock agent listener for CID 3
	ln, err := transport.Listen(ctx, 3)
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Keep connection alive — just read and discard
		buf := make([]byte, 1024)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	conn, err := pool.Get(ctx, "agent-1", 3)
	require.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestConnPool_GetReturnsSameConnection(t *testing.T) {
	transport := proxy.NewTCPTransport(9500)
	pool := proxy.NewConnPool(transport)
	ctx := context.Background()

	ln, err := transport.Listen(ctx, 3)
	require.NoError(t, err)
	defer ln.Close()

	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	conn1, err := pool.Get(ctx, "agent-1", 3)
	require.NoError(t, err)

	conn2, err := pool.Get(ctx, "agent-1", 3)
	require.NoError(t, err)

	// Should be the same *AgentConn
	assert.Same(t, conn1, conn2)
}

func TestConnPool_Remove(t *testing.T) {
	transport := proxy.NewTCPTransport(9600)
	pool := proxy.NewConnPool(transport)
	ctx := context.Background()

	ln, err := transport.Listen(ctx, 3)
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1024)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					return
				}
			}
		}
	}()

	_, err = pool.Get(ctx, "agent-1", 3)
	require.NoError(t, err)

	pool.Remove("agent-1")

	// Next Get should create a new connection
	conn2, err := pool.Get(ctx, "agent-1", 3)
	require.NoError(t, err)
	assert.NotNil(t, conn2)
}

func TestConnPool_GetFailsWhenNoListener(t *testing.T) {
	transport := proxy.NewTCPTransport(9700)
	pool := proxy.NewConnPool(transport)

	_, err := pool.Get(context.Background(), "agent-99", 99)
	assert.Error(t, err)
}
