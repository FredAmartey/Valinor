package proxy_test

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

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

func TestAgentConn_RequestRoutesByFrameID_Concurrent(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	sConn := proxy.NewAgentConn(server)
	cConn := proxy.NewAgentConn(client)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		first, err := sConn.Recv(ctx)
		if err != nil {
			return
		}
		second, err := sConn.Recv(ctx)
		if err != nil {
			return
		}

		type payload struct {
			Content string `json:"content"`
		}
		var firstPayload payload
		var secondPayload payload
		_ = json.Unmarshal(first.Payload, &firstPayload)
		_ = json.Unmarshal(second.Payload, &secondPayload)

		firstReply := "second"
		if firstPayload.Content == "hello-first" {
			firstReply = "first"
		}
		secondReply := "second"
		if secondPayload.Content == "hello-first" {
			secondReply = "first"
		}

		// Intentionally reply out of order to prove ID-based routing.
		_ = sConn.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      second.ID,
			Payload: json.RawMessage(`{"content":"` + secondReply + `","done":true}`),
		})
		_ = sConn.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      first.ID,
			Payload: json.RawMessage(`{"content":"` + firstReply + `","done":true}`),
		})
	}()

	type result struct {
		id      string
		payload string
		err     error
	}
	results := make(chan result, 2)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		req, err := cConn.SendRequest(ctx, proxy.Frame{
			Type:    proxy.TypeMessage,
			ID:      "req-first",
			Payload: json.RawMessage(`{"content":"hello-first"}`),
		})
		if err != nil {
			results <- result{err: err}
			return
		}
		defer req.Close()

		reply, err := req.Recv(ctx)
		if err != nil {
			results <- result{err: err}
			return
		}
		results <- result{id: reply.ID, payload: string(reply.Payload)}
	}()
	go func() {
		defer wg.Done()
		req, err := cConn.SendRequest(ctx, proxy.Frame{
			Type:    proxy.TypeMessage,
			ID:      "req-second",
			Payload: json.RawMessage(`{"content":"hello-second"}`),
		})
		if err != nil {
			results <- result{err: err}
			return
		}
		defer req.Close()

		reply, err := req.Recv(ctx)
		if err != nil {
			results <- result{err: err}
			return
		}
		results <- result{id: reply.ID, payload: string(reply.Payload)}
	}()

	wg.Wait()
	close(results)

	got := map[string]string{}
	for res := range results {
		require.NoError(t, res.err)
		got[res.id] = res.payload
	}

	require.Len(t, got, 2)
	assert.Contains(t, got["req-first"], `"first"`)
	assert.Contains(t, got["req-second"], `"second"`)
}

func TestAgentConn_RequestTimeoutUnregistersWaiter(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	sConn := proxy.NewAgentConn(server)
	cConn := proxy.NewAgentConn(client)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_, err := sConn.Recv(ctx)
		if err != nil {
			return
		}
		// First request intentionally gets no reply so it times out.
		_, err = sConn.Recv(ctx)
		if err != nil {
			return
		}
		_ = sConn.Send(ctx, proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      "req-timeout",
			Payload: json.RawMessage(`{"content":"after-timeout","done":true}`),
		})
	}()

	firstReq, err := cConn.SendRequest(ctx, proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "req-timeout",
		Payload: json.RawMessage(`{"content":"first"}`),
	})
	require.NoError(t, err)
	firstRecvCtx, firstCancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer firstCancel()
	_, err = firstReq.Recv(firstRecvCtx)
	require.Error(t, err)
	firstReq.Close()

	secondReq, err := cConn.SendRequest(ctx, proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "req-timeout",
		Payload: json.RawMessage(`{"content":"second"}`),
	})
	require.NoError(t, err)
	defer secondReq.Close()

	reply, err := secondReq.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, "req-timeout", reply.ID)
	assert.Contains(t, string(reply.Payload), `"after-timeout"`)
}

func TestAgentConn_RequestFailsWhenRecvLoopDies(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	sConn := proxy.NewAgentConn(server)
	cConn := proxy.NewAgentConn(client)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_, err := sConn.Recv(ctx)
		if err == nil {
			_ = sConn.Close()
		}
	}()

	req, err := cConn.SendRequest(ctx, proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "req-close",
		Payload: json.RawMessage(`{"content":"hello"}`),
	})
	require.NoError(t, err)
	defer req.Close()

	_, err = req.Recv(ctx)
	require.Error(t, err)
}
