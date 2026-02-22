package proxy_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestTCPTransport_DialAndListen(t *testing.T) {
	transport := proxy.NewTCPTransport(9200)
	ctx := context.Background()

	// Start listener for CID 3
	ln, err := transport.Listen(ctx, 3)
	require.NoError(t, err)
	defer ln.Close()

	// Accept in background
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	// Dial CID 3
	conn, err := transport.Dial(ctx, 3)
	require.NoError(t, err)
	defer conn.Close()

	// Verify connection works
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	serverConn := <-accepted
	defer serverConn.Close()
	buf := make([]byte, 5)
	n, err := serverConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))
}

func TestTCPTransport_DialUnlistenedCID(t *testing.T) {
	transport := proxy.NewTCPTransport(9300)
	ctx := context.Background()

	_, err := transport.Dial(ctx, 999)
	assert.Error(t, err)
}
