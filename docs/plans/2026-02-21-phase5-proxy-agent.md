# Phase 5: Proxy + In-Guest Agent Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the vsock communication layer, proxy module, and in-guest valinor-agent binary so that clients can send messages to agents, receive streaming responses, and push config updates to running VMs.

**Architecture:** A shared `internal/proxy` package implements the length-prefixed JSON wire protocol, transport abstraction (vsock/TCP), connection pooling, and HTTP handlers for messaging. A separate `cmd/valinor-agent` binary runs inside each MicroVM, bridging control plane commands to OpenClaw via HTTP proxy at localhost:8081. All tests use TCPTransport or net.Pipe() — no vsock required.

**Tech Stack:** Go 1.25, net.Pipe() for unit tests, httptest for handler tests, SSE for streaming, length-prefixed JSON wire protocol.

**Design doc:** `docs/plans/2026-02-21-phase5-proxy-agent-design.md`

---

### Task 1: Wire Protocol — Frame Types and Encode/Decode

**Files:**
- Create: `internal/proxy/protocol.go`
- Create: `internal/proxy/protocol_test.go`

**Step 1: Write the failing test**

Create `internal/proxy/protocol_test.go`:

```go
package proxy_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestEncodeFrame(t *testing.T) {
	f := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "req-1",
		Payload: json.RawMessage(`{"role":"user","content":"hello"}`),
	}

	data, err := proxy.EncodeFrame(f)
	require.NoError(t, err)

	// First 4 bytes = big-endian uint32 payload length
	payloadLen := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	assert.Equal(t, uint32(len(data)-4), payloadLen)

	// Remaining bytes are valid JSON matching the frame
	var decoded proxy.Frame
	err = json.Unmarshal(data[4:], &decoded)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeMessage, decoded.Type)
	assert.Equal(t, "req-1", decoded.ID)
}

func TestDecodeFrame(t *testing.T) {
	original := proxy.Frame{
		Type:    proxy.TypeChunk,
		ID:      "req-2",
		Payload: json.RawMessage(`{"content":"hi","done":false}`),
	}

	data, err := proxy.EncodeFrame(original)
	require.NoError(t, err)

	decoded, n, err := proxy.DecodeFrame(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.ID, decoded.ID)
}

func TestDecodeFrame_InsufficientData(t *testing.T) {
	// Less than 4 bytes header
	_, _, err := proxy.DecodeFrame([]byte{0, 0})
	assert.Error(t, err)
}

func TestDecodeFrame_TruncatedPayload(t *testing.T) {
	// Header says 100 bytes but only 5 available
	data := []byte{0, 0, 0, 100, '{', '}'}
	_, _, err := proxy.DecodeFrame(data)
	assert.Error(t, err)
}

func TestFrameTypeConstants(t *testing.T) {
	// Verify all type constants are defined
	types := []string{
		proxy.TypeConfigUpdate,
		proxy.TypeMessage,
		proxy.TypeContextUpdate,
		proxy.TypePing,
		proxy.TypeHeartbeat,
		proxy.TypeChunk,
		proxy.TypeConfigAck,
		proxy.TypeToolBlocked,
		proxy.TypePong,
		proxy.TypeError,
	}
	for _, typ := range types {
		assert.NotEmpty(t, typ)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/... -v -run TestEncodeFrame`
Expected: FAIL — package does not exist / functions not defined

**Step 3: Write minimal implementation**

Create `internal/proxy/protocol.go`:

```go
package proxy

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Frame type constants — Control Plane → Agent
const (
	TypeConfigUpdate  = "config_update"
	TypeMessage       = "message"
	TypeContextUpdate = "context_update"
	TypePing          = "ping"
)

// Frame type constants — Agent → Control Plane
const (
	TypeHeartbeat   = "heartbeat"
	TypeChunk       = "chunk"
	TypeConfigAck   = "config_ack"
	TypeToolBlocked = "tool_blocked"
	TypePong        = "pong"
	TypeError       = "error"
)

// Frame is the envelope for all vsock wire messages.
type Frame struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

// MaxFrameSize limits frame payloads to 4 MB.
const MaxFrameSize = 4 << 20

// EncodeFrame serializes a Frame into length-prefixed wire format:
// [4 bytes: big-endian uint32 payload length] [N bytes: JSON payload]
func EncodeFrame(f Frame) ([]byte, error) {
	payload, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("marshaling frame: %w", err)
	}

	if len(payload) > MaxFrameSize {
		return nil, fmt.Errorf("frame payload %d bytes exceeds max %d", len(payload), MaxFrameSize)
	}

	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)
	return buf, nil
}

// DecodeFrame reads a length-prefixed frame from data.
// Returns the frame, total bytes consumed, and any error.
func DecodeFrame(data []byte) (Frame, int, error) {
	if len(data) < 4 {
		return Frame{}, 0, errors.New("insufficient data for frame header")
	}

	payloadLen := binary.BigEndian.Uint32(data[:4])
	if payloadLen > MaxFrameSize {
		return Frame{}, 0, fmt.Errorf("frame payload %d bytes exceeds max %d", payloadLen, MaxFrameSize)
	}

	total := 4 + int(payloadLen)
	if len(data) < total {
		return Frame{}, 0, errors.New("insufficient data for frame payload")
	}

	var f Frame
	if err := json.Unmarshal(data[4:total], &f); err != nil {
		return Frame{}, 0, fmt.Errorf("unmarshaling frame: %w", err)
	}

	return f, total, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/... -v -count=1`
Expected: PASS (all 5 tests)

**Step 5: Commit**

```bash
git add internal/proxy/protocol.go internal/proxy/protocol_test.go
git commit -m "feat(proxy): add wire protocol Frame types and encode/decode"
```

---

### Task 2: Transport Interface and TCPTransport

**Files:**
- Create: `internal/proxy/transport.go`
- Create: `internal/proxy/transport_test.go`

**Step 1: Write the failing test**

Create `internal/proxy/transport_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/... -v -run TestTCPTransport`
Expected: FAIL — `NewTCPTransport` not defined

**Step 3: Write minimal implementation**

Create `internal/proxy/transport.go`:

```go
package proxy

import (
	"context"
	"fmt"
	"net"
)

// Transport abstracts vsock vs TCP for host↔guest communication.
type Transport interface {
	Dial(ctx context.Context, cid uint32) (net.Conn, error)
	Listen(ctx context.Context, port uint32) (net.Listener, error)
}

// TCPTransport maps vsock CID to localhost:basePort+CID for dev/testing.
type TCPTransport struct {
	basePort int
}

// NewTCPTransport creates a TCP transport that maps CID N to localhost:basePort+N.
func NewTCPTransport(basePort int) *TCPTransport {
	return &TCPTransport{basePort: basePort}
}

func (t *TCPTransport) Dial(ctx context.Context, cid uint32) (net.Conn, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", t.basePort+int(cid))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialing CID %d at %s: %w", cid, addr, err)
	}
	return conn, nil
}

func (t *TCPTransport) Listen(ctx context.Context, port uint32) (net.Listener, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", t.basePort+int(port))
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening on CID %d at %s: %w", port, addr, err)
	}
	return ln, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/... -v -run TestTCPTransport -count=1`
Expected: PASS (both tests)

**Step 5: Commit**

```bash
git add internal/proxy/transport.go internal/proxy/transport_test.go
git commit -m "feat(proxy): add Transport interface and TCPTransport for dev"
```

---

### Task 3: AgentConn — Send/Recv over net.Conn

**Files:**
- Create: `internal/proxy/conn.go`
- Create: `internal/proxy/conn_test.go`

**Step 1: Write the failing test**

Create `internal/proxy/conn_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/... -v -run TestAgentConn`
Expected: FAIL — `NewAgentConn` not defined

**Step 3: Write minimal implementation**

Create `internal/proxy/conn.go`:

```go
package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// AgentConn wraps a net.Conn with the length-prefixed JSON protocol.
type AgentConn struct {
	conn   net.Conn
	mu     sync.Mutex // serializes writes
	readMu sync.Mutex // serializes reads
}

// NewAgentConn wraps a raw connection with frame send/recv capabilities.
func NewAgentConn(conn net.Conn) *AgentConn {
	return &AgentConn{conn: conn}
}

// Send writes a length-prefixed Frame to the connection.
func (c *AgentConn) Send(_ context.Context, frame Frame) error {
	data, err := EncodeFrame(frame)
	if err != nil {
		return fmt.Errorf("encoding frame: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("writing frame: %w", err)
	}
	return nil
}

// Recv reads a length-prefixed Frame from the connection.
func (c *AgentConn) Recv(_ context.Context) (Frame, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Read 4-byte header
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return Frame{}, fmt.Errorf("reading frame header: %w", err)
	}

	payloadLen := binary.BigEndian.Uint32(header)
	if payloadLen > MaxFrameSize {
		return Frame{}, fmt.Errorf("frame payload %d bytes exceeds max %d", payloadLen, MaxFrameSize)
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return Frame{}, fmt.Errorf("reading frame payload: %w", err)
	}

	// Reconstruct full buffer and decode
	buf := append(header, payload...)
	frame, _, err := DecodeFrame(buf)
	if err != nil {
		return Frame{}, fmt.Errorf("decoding frame: %w", err)
	}

	return frame, nil
}

// Close closes the underlying connection.
func (c *AgentConn) Close() error {
	return c.conn.Close()
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/... -v -run TestAgentConn -count=1`
Expected: PASS (all 3 tests)

**Step 5: Commit**

```bash
git add internal/proxy/conn.go internal/proxy/conn_test.go
git commit -m "feat(proxy): add AgentConn with Send/Recv over net.Conn"
```

---

### Task 4: ConnPool — Lazy Connection Pooling per Agent

**Files:**
- Create: `internal/proxy/pool.go`
- Create: `internal/proxy/pool_test.go`

**Step 1: Write the failing test**

Create `internal/proxy/pool_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/... -v -run TestConnPool`
Expected: FAIL — `NewConnPool` not defined

**Step 3: Write minimal implementation**

Create `internal/proxy/pool.go`:

```go
package proxy

import (
	"context"
	"fmt"
	"sync"
)

// ConnPool maintains open connections to agents, keyed by agent instance ID.
// Connections are created lazily on first Get.
type ConnPool struct {
	transport Transport
	mu        sync.Mutex
	conns     map[string]*AgentConn
}

// NewConnPool creates a ConnPool using the given transport.
func NewConnPool(transport Transport) *ConnPool {
	return &ConnPool{
		transport: transport,
		conns:     make(map[string]*AgentConn),
	}
}

// Get returns the existing connection for an agent, or dials a new one.
func (p *ConnPool) Get(ctx context.Context, agentID string, cid uint32) (*AgentConn, error) {
	p.mu.Lock()
	if conn, ok := p.conns[agentID]; ok {
		p.mu.Unlock()
		return conn, nil
	}
	p.mu.Unlock()

	// Dial outside lock to avoid blocking other agents
	raw, err := p.transport.Dial(ctx, cid)
	if err != nil {
		return nil, fmt.Errorf("dialing agent %s (CID %d): %w", agentID, cid, err)
	}

	conn := NewAgentConn(raw)

	p.mu.Lock()
	// Check again in case another goroutine dialed concurrently
	if existing, ok := p.conns[agentID]; ok {
		p.mu.Unlock()
		_ = conn.Close() // close the duplicate
		return existing, nil
	}
	p.conns[agentID] = conn
	p.mu.Unlock()

	return conn, nil
}

// Remove closes and removes a connection from the pool.
func (p *ConnPool) Remove(agentID string) {
	p.mu.Lock()
	conn, ok := p.conns[agentID]
	delete(p.conns, agentID)
	p.mu.Unlock()

	if ok {
		_ = conn.Close()
	}
}

// Close closes all connections in the pool.
func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, conn := range p.conns {
		_ = conn.Close()
		delete(p.conns, id)
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/... -v -run TestConnPool -count=1`
Expected: PASS (all 4 tests)

**Step 5: Commit**

```bash
git add internal/proxy/pool.go internal/proxy/pool_test.go
git commit -m "feat(proxy): add ConnPool with lazy dialing per agent"
```

---

### Task 5: Proxy Config — Add ProxyConfig to Config Struct

**Files:**
- Modify: `internal/platform/config/config.go`

**Step 1: Add ProxyConfig to config**

Add to `internal/platform/config/config.go`:

```go
// Add field to Config struct:
type Config struct {
	Server       ServerConfig       `koanf:"server"`
	Database     DatabaseConfig     `koanf:"database"`
	Log          LogConfig          `koanf:"log"`
	Auth         AuthConfig         `koanf:"auth"`
	Orchestrator OrchestratorConfig `koanf:"orchestrator"`
	Proxy        ProxyConfig        `koanf:"proxy"`
}

// Add new type:
type ProxyConfig struct {
	Transport      string `koanf:"transport"`       // "tcp" or "vsock"
	TCPBasePort    int    `koanf:"tcp_base_port"`   // base port for TCP transport (dev)
	MessageTimeout int    `koanf:"message_timeout"` // seconds, default 60
	ConfigTimeout  int    `koanf:"config_timeout"`  // seconds, default 5
	PingTimeout    int    `koanf:"ping_timeout"`    // seconds, default 3
}
```

Add defaults to `Load()`:

```go
"proxy.transport":       "tcp",
"proxy.tcp_base_port":   9100,
"proxy.message_timeout": 60,
"proxy.config_timeout":  5,
"proxy.ping_timeout":    3,
```

**Step 2: Run tests to verify nothing broke**

Run: `go test ./internal/platform/config/... -v -short -count=1`
Expected: PASS (or no tests — either way, no compile error)

Run: `go build ./cmd/valinor`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add internal/platform/config/config.go
git commit -m "feat(config): add ProxyConfig for transport and timeouts"
```

---

### Task 6: Proxy HTTP Handler — POST /agents/:id/message

**Files:**
- Create: `internal/proxy/handler.go`
- Create: `internal/proxy/handler_test.go`

**Step 1: Write the failing test**

Create `internal/proxy/handler_test.go`:

```go
package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/proxy"
)

// mockAgentStore implements the interface proxy.Handler needs to look up agents.
type mockAgentStore struct {
	agents map[string]*orchestrator.AgentInstance
}

func (m *mockAgentStore) GetByID(_ context.Context, id string) (*orchestrator.AgentInstance, error) {
	inst, ok := m.agents[id]
	if !ok {
		return nil, orchestrator.ErrVMNotFound
	}
	return inst, nil
}

func TestHandleMessage_Success(t *testing.T) {
	transport := proxy.NewTCPTransport(9800)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	cid := uint32(3)
	agentID := "agent-1"
	tenantID := "tenant-1"

	store := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID: {
				ID:       agentID,
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusRunning,
			},
		},
	}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 5 * time.Second,
	})

	// Start mock agent that echoes back as a done chunk
	ctx := context.Background()
	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	go mockAgent(t, ln)

	// Send message
	body := `{"role":"user","content":"hello"}`
	req := httptest.NewRequest("POST", "/agents/"+agentID+"/message", bytes.NewBufferString(body))
	req.SetPathValue("id", agentID)
	w := httptest.NewRecorder()

	handler.HandleMessage(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "content")
}

func TestHandleMessage_AgentNotFound(t *testing.T) {
	transport := proxy.NewTCPTransport(9810)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	store := &mockAgentStore{agents: map[string]*orchestrator.AgentInstance{}}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 5 * time.Second,
	})

	body := `{"role":"user","content":"hello"}`
	req := httptest.NewRequest("POST", "/agents/bad-id/message", bytes.NewBufferString(body))
	req.SetPathValue("id", "bad-id")
	w := httptest.NewRecorder()

	handler.HandleMessage(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleMessage_AgentNotRunning(t *testing.T) {
	transport := proxy.NewTCPTransport(9820)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	agentID := "agent-1"
	tenantID := "tenant-1"
	cid := uint32(3)

	store := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID: {
				ID:       agentID,
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusProvisioning,
			},
		},
	}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 5 * time.Second,
	})

	body := `{"role":"user","content":"hello"}`
	req := httptest.NewRequest("POST", "/agents/"+agentID+"/message", bytes.NewBufferString(body))
	req.SetPathValue("id", agentID)
	w := httptest.NewRecorder()

	handler.HandleMessage(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// mockAgent accepts one connection, reads a message frame, and replies with a done chunk.
func mockAgent(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	ac := proxy.NewAgentConn(conn)
	ctx := context.Background()

	frame, err := ac.Recv(ctx)
	if err != nil {
		return
	}

	reply := proxy.Frame{
		Type:    proxy.TypeChunk,
		ID:      frame.ID,
		Payload: json.RawMessage(`{"content":"Echo: hello","done":true}`),
	}
	_ = ac.Send(ctx, reply)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/... -v -run TestHandleMessage`
Expected: FAIL — `NewHandler`, `HandleMessage`, `HandlerConfig` not defined

**Step 3: Write minimal implementation**

Create `internal/proxy/handler.go`:

```go
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)

// AgentLookup provides agent instance lookups for the proxy handler.
type AgentLookup interface {
	GetByID(ctx context.Context, id string) (*orchestrator.AgentInstance, error)
}

// HandlerConfig holds proxy handler configuration.
type HandlerConfig struct {
	MessageTimeout time.Duration
	ConfigTimeout  time.Duration
	PingTimeout    time.Duration
}

// Handler serves proxy HTTP endpoints for agent communication.
type Handler struct {
	pool   *ConnPool
	agents AgentLookup
	cfg    HandlerConfig
}

// NewHandler creates a proxy Handler.
func NewHandler(pool *ConnPool, agents AgentLookup, cfg HandlerConfig) *Handler {
	if cfg.MessageTimeout <= 0 {
		cfg.MessageTimeout = 60 * time.Second
	}
	if cfg.ConfigTimeout <= 0 {
		cfg.ConfigTimeout = 5 * time.Second
	}
	if cfg.PingTimeout <= 0 {
		cfg.PingTimeout = 3 * time.Second
	}
	return &Handler{pool: pool, agents: agents, cfg: cfg}
}

// HandleMessage sends a user message to an agent and returns the full response.
// POST /agents/:id/message
func (h *Handler) HandleMessage(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	inst, err := h.agents.GetByID(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, orchestrator.ErrVMNotFound) {
			writeProxyJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeProxyJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	if inst.Status != orchestrator.StatusRunning {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent not running"})
		return
	}

	if inst.VsockCID == nil {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent has no vsock CID"})
		return
	}

	// Read request body
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Get or create connection
	conn, err := h.pool.Get(r.Context(), agentID, *inst.VsockCID)
	if err != nil {
		slog.Error("proxy dial failed", "agent", agentID, "cid", *inst.VsockCID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent unreachable"})
		return
	}

	// Send message frame
	reqID := uuid.New().String()
	frame := Frame{
		Type:    TypeMessage,
		ID:      reqID,
		Payload: body,
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.MessageTimeout)
	defer cancel()

	if err := conn.Send(ctx, frame); err != nil {
		h.pool.Remove(agentID)
		slog.Error("proxy send failed", "agent", agentID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}

	// Collect chunks until done
	var contentParts []string
	for {
		reply, err := conn.Recv(ctx)
		if err != nil {
			h.pool.Remove(agentID)
			slog.Error("proxy recv failed", "agent", agentID, "error", err)
			writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "recv failed"})
			return
		}

		switch reply.Type {
		case TypeChunk:
			var chunk struct {
				Content string `json:"content"`
				Done    bool   `json:"done"`
			}
			if err := json.Unmarshal(reply.Payload, &chunk); err != nil {
				writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid chunk"})
				return
			}
			contentParts = append(contentParts, chunk.Content)
			if chunk.Done {
				writeProxyJSON(w, http.StatusOK, map[string]string{
					"content": strings.Join(contentParts, ""),
				})
				return
			}

		case TypeError:
			var agentErr struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(reply.Payload, &agentErr); err != nil {
				writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent error"})
				return
			}
			writeProxyJSON(w, http.StatusBadGateway, map[string]string{
				"error": fmt.Sprintf("agent error: %s", agentErr.Message),
			})
			return

		case TypeToolBlocked:
			var blocked struct {
				ToolName string `json:"tool_name"`
				Reason   string `json:"reason"`
			}
			_ = json.Unmarshal(reply.Payload, &blocked)
			writeProxyJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("tool blocked: %s", blocked.ToolName),
			})
			return
		}
	}
}

func writeProxyJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/... -v -run TestHandleMessage -count=1`
Expected: PASS (all 3 tests)

**Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "feat(proxy): add HandleMessage endpoint for agent messaging"
```

---

### Task 7: Proxy HTTP Handler — GET /agents/:id/stream (SSE)

**Files:**
- Modify: `internal/proxy/handler.go` (add HandleStream method)
- Modify: `internal/proxy/handler_test.go` (add SSE tests)

**Step 1: Write the failing test**

Add to `internal/proxy/handler_test.go`:

```go
func TestHandleStream_SSE(t *testing.T) {
	transport := proxy.NewTCPTransport(9830)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	cid := uint32(3)
	agentID := "agent-1"
	tenantID := "tenant-1"

	store := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID: {
				ID:       agentID,
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusRunning,
			},
		},
	}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 5 * time.Second,
	})

	ctx := context.Background()
	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	// Mock agent that sends two chunks
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		chunk1 := proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"Hello ","done":false}`),
		}
		_ = ac.Send(ctx, chunk1)

		chunk2 := proxy.Frame{
			Type:    proxy.TypeChunk,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"content":"World","done":true}`),
		}
		_ = ac.Send(ctx, chunk2)
	}()

	body := `{"role":"user","content":"hello"}`
	req := httptest.NewRequest("GET", "/agents/"+agentID+"/stream?message="+body, nil)
	req.SetPathValue("id", agentID)
	w := httptest.NewRecorder()

	handler.HandleStream(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))

	// Verify SSE format
	respBody := w.Body.String()
	assert.Contains(t, respBody, "event: chunk")
	assert.Contains(t, respBody, "event: done")
	assert.Contains(t, respBody, `"content":"Hello "`)
	assert.Contains(t, respBody, `"content":"World"`)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/... -v -run TestHandleStream`
Expected: FAIL — `HandleStream` not defined

**Step 3: Write minimal implementation**

Add to `internal/proxy/handler.go`:

```go
// HandleStream sends a user message and streams response chunks via SSE.
// GET /agents/:id/stream?message={json}
func (h *Handler) HandleStream(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	inst, err := h.agents.GetByID(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, orchestrator.ErrVMNotFound) {
			writeProxyJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeProxyJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	if inst.Status != orchestrator.StatusRunning {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent not running"})
		return
	}

	if inst.VsockCID == nil {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent has no vsock CID"})
		return
	}

	// Read message from query param
	messageJSON := r.URL.Query().Get("message")
	if messageJSON == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "message query param required"})
		return
	}

	conn, err := h.pool.Get(r.Context(), agentID, *inst.VsockCID)
	if err != nil {
		slog.Error("proxy dial failed", "agent", agentID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent unreachable"})
		return
	}

	reqID := uuid.New().String()
	frame := Frame{
		Type:    TypeMessage,
		ID:      reqID,
		Payload: json.RawMessage(messageJSON),
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.MessageTimeout)
	defer cancel()

	if err := conn.Send(ctx, frame); err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)

	for {
		reply, err := conn.Recv(ctx)
		if err != nil {
			h.pool.Remove(agentID)
			return
		}

		switch reply.Type {
		case TypeChunk:
			var chunk struct {
				Content string `json:"content"`
				Done    bool   `json:"done"`
			}
			if err := json.Unmarshal(reply.Payload, &chunk); err != nil {
				return
			}

			fmt.Fprintf(w, "event: chunk\ndata: %s\n\n", string(reply.Payload))
			if flusher != nil {
				flusher.Flush()
			}

			if chunk.Done {
				fmt.Fprintf(w, "event: done\ndata: {}\n\n")
				if flusher != nil {
					flusher.Flush()
				}
				return
			}

		case TypeError:
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(reply.Payload))
			if flusher != nil {
				flusher.Flush()
			}
			return

		case TypeToolBlocked:
			fmt.Fprintf(w, "event: tool_blocked\ndata: %s\n\n", string(reply.Payload))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/... -v -run TestHandleStream -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "feat(proxy): add HandleStream SSE endpoint for streaming responses"
```

---

### Task 8: Proxy HTTP Handler — POST /agents/:id/context

**Files:**
- Modify: `internal/proxy/handler.go` (add HandleContext method)
- Modify: `internal/proxy/handler_test.go` (add context tests)

**Step 1: Write the failing test**

Add to `internal/proxy/handler_test.go`:

```go
func TestHandleContext_Success(t *testing.T) {
	transport := proxy.NewTCPTransport(9840)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	cid := uint32(3)
	agentID := "agent-1"
	tenantID := "tenant-1"

	store := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID: {
				ID:       agentID,
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusRunning,
			},
		},
	}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		ConfigTimeout: 5 * time.Second,
	})

	ctx := context.Background()
	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	// Mock agent that acks context updates
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		ack := proxy.Frame{
			Type:    proxy.TypeConfigAck,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"applied":true}`),
		}
		_ = ac.Send(ctx, ack)
	}()

	body := `{"context":"The player is 23 years old"}`
	req := httptest.NewRequest("POST", "/agents/"+agentID+"/context", bytes.NewBufferString(body))
	req.SetPathValue("id", agentID)
	w := httptest.NewRecorder()

	handler.HandleContext(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/... -v -run TestHandleContext`
Expected: FAIL — `HandleContext` not defined

**Step 3: Write minimal implementation**

Add to `internal/proxy/handler.go`:

```go
// HandleContext pushes a context update to a running agent.
// POST /agents/:id/context
func (h *Handler) HandleContext(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	inst, err := h.agents.GetByID(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, orchestrator.ErrVMNotFound) {
			writeProxyJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeProxyJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	if inst.Status != orchestrator.StatusRunning {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent not running"})
		return
	}

	if inst.VsockCID == nil {
		writeProxyJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent has no vsock CID"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProxyJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	conn, err := h.pool.Get(r.Context(), agentID, *inst.VsockCID)
	if err != nil {
		slog.Error("proxy dial failed", "agent", agentID, "error", err)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent unreachable"})
		return
	}

	reqID := uuid.New().String()
	frame := Frame{
		Type:    TypeContextUpdate,
		ID:      reqID,
		Payload: body,
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.ConfigTimeout)
	defer cancel()

	if err := conn.Send(ctx, frame); err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "send failed"})
		return
	}

	// Wait for ack
	reply, err := conn.Recv(ctx)
	if err != nil {
		h.pool.Remove(agentID)
		writeProxyJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "ack timeout"})
		return
	}

	if reply.Type == TypeError {
		writeProxyJSON(w, http.StatusBadGateway, map[string]string{"error": "agent rejected context update"})
		return
	}

	writeProxyJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/... -v -run TestHandleContext -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "feat(proxy): add HandleContext endpoint for pushing context updates"
```

---

### Task 9: Config Push — PushConfig Function

**Files:**
- Create: `internal/proxy/push.go`
- Create: `internal/proxy/push_test.go`

**Step 1: Write the failing test**

Create `internal/proxy/push_test.go`:

```go
package proxy_test

import (
	"context"
	"encoding/json"
	"net"
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
		conn, err := ln.Accept()
		if err != nil {
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

	err = proxy.PushConfig(ctx, pool, "agent-1", cid, config, allowlist, 5*time.Second)
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

	err := proxy.PushConfig(context.Background(), pool, "agent-bad", 99, nil, nil, 2*time.Second)
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
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Read but don't reply — let it timeout
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		// Hold connection open
		<-ctx.Done()
		conn.Close()
	}()

	err = proxy.PushConfig(ctx, pool, "agent-1", cid, nil, nil, 500*time.Millisecond)
	assert.Error(t, err)
}

func startMockListener(t *testing.T, transport *proxy.TCPTransport, cid uint32) net.Listener {
	t.Helper()
	ln, err := transport.Listen(context.Background(), cid)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	return ln
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/... -v -run TestPushConfig`
Expected: FAIL — `PushConfig` not defined

**Step 3: Write minimal implementation**

Create `internal/proxy/push.go`:

```go
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PushConfig sends a config_update frame to a running agent and waits for ack.
func PushConfig(ctx context.Context, pool *ConnPool, agentID string, cid uint32, config map[string]any, toolAllowlist []string, timeout time.Duration) error {
	conn, err := pool.Get(ctx, agentID, cid)
	if err != nil {
		return fmt.Errorf("connecting to agent %s: %w", agentID, err)
	}

	payload := struct {
		Config        map[string]any `json:"config"`
		ToolAllowlist []string       `json:"tool_allowlist"`
	}{
		Config:        config,
		ToolAllowlist: toolAllowlist,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling config payload: %w", err)
	}

	frame := Frame{
		Type:    TypeConfigUpdate,
		ID:      uuid.New().String(),
		Payload: json.RawMessage(payloadJSON),
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := conn.Send(ctx, frame); err != nil {
		pool.Remove(agentID)
		return fmt.Errorf("sending config to agent %s: %w", agentID, err)
	}

	// Wait for ack
	reply, err := conn.Recv(ctx)
	if err != nil {
		pool.Remove(agentID)
		return fmt.Errorf("waiting for config ack from agent %s: %w", agentID, err)
	}

	if reply.Type == TypeError {
		return fmt.Errorf("agent %s rejected config update: %s", agentID, string(reply.Payload))
	}

	return nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/... -v -run TestPushConfig -count=1`
Expected: PASS (Success and NoListener pass; Timeout may need `conn.SetDeadline` — adjust if needed)

Note: The Timeout test relies on `conn.Recv` timing out. Since `net.Pipe()` doesn't support deadlines but TCP does, and we use TCPTransport, the context timeout should work via a wrapper. If the test hangs, update `AgentConn.Recv` to set a read deadline from the context:

```go
// In conn.go, update Recv:
func (c *AgentConn) Recv(ctx context.Context) (Frame, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Set deadline from context if available
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
		defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	}
	// ... rest unchanged
```

**Step 5: Commit**

```bash
git add internal/proxy/push.go internal/proxy/push_test.go internal/proxy/conn.go
git commit -m "feat(proxy): add PushConfig for vsock config delivery with ack"
```

---

### Task 10: Integrate Config Push into Orchestrator HandleConfigure

**Files:**
- Modify: `internal/orchestrator/handler.go:169-236` (add proxy push after DB update)

**Step 1: Write the failing test**

Note: The existing HandleConfigure already works without proxy push. This change adds a best-effort vsock push when the agent is running. Since the proxy push is best-effort (log warning on failure), we modify the handler to accept an optional `ConfigPusher` interface.

Add to a new test file `internal/orchestrator/handler_proxy_test.go`:

```go
package orchestrator_test

// This test verifies that HandleConfigure calls ConfigPusher when the agent is running.
// See the integration test in internal/proxy/ for full end-to-end push verification.
```

Actually, the integration is simpler: just modify the orchestrator Handler to accept an optional `ConfigPusher` and call it. The test can verify via a mock. But per the design doc, the orchestrator handler just calls `proxy.PushConfig()`. The simplest approach: add a `ConfigPusher` field to the handler.

**Step 1 (actual): Modify handler to accept ConfigPusher**

In `internal/orchestrator/handler.go`, add:

```go
// ConfigPusher pushes config to a running agent over vsock.
type ConfigPusher interface {
	PushConfig(ctx context.Context, agentID string, cid uint32, config map[string]any, toolAllowlist []string) error
}
```

Modify the `Handler` struct:

```go
type Handler struct {
	manager      *Manager
	configPusher ConfigPusher // optional, nil = no vsock push
}

func NewHandler(manager *Manager, pusher ConfigPusher) *Handler {
	return &Handler{manager: manager, configPusher: pusher}
}
```

In `HandleConfigure`, after the successful `UpdateConfig` call and before the final `GetByID`, add:

```go
// Best-effort push to running agent via vsock
if h.configPusher != nil && inst.Status == StatusRunning && inst.VsockCID != nil {
	if pushErr := h.configPusher.PushConfig(r.Context(), id, *inst.VsockCID, req.Config, req.ToolAllowlist); pushErr != nil {
		slog.Warn("config push to agent failed", "id", id, "error", pushErr)
	}
}
```

**Step 2: Update main.go to pass nil for now**

In `cmd/valinor/main.go`, change:

```go
agentHandler = orchestrator.NewHandler(orchManager, nil) // no proxy push yet
```

The proxy push will be wired in Task 14.

**Step 3: Run tests to verify nothing broke**

Run: `go test ./internal/orchestrator/... -v -short -count=1`
Expected: PASS

Run: `go build ./cmd/valinor`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add internal/orchestrator/handler.go cmd/valinor/main.go
git commit -m "feat(orchestrator): add optional ConfigPusher for vsock config push"
```

---

### Task 11: In-Guest Agent — Main Binary Scaffold

**Files:**
- Create: `cmd/valinor-agent/main.go`

**Step 1: Create the binary entrypoint**

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "valinor-agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	transportFlag := flag.String("transport", "vsock", "transport type: vsock or tcp")
	portFlag := flag.Int("port", 1024, "listen port (vsock port or TCP port)")
	openclawURL := flag.String("openclaw-url", "http://localhost:8081", "OpenClaw API URL")
	flag.Parse()

	slog.Info("valinor-agent starting",
		"transport", *transportFlag,
		"port", *portFlag,
		"openclaw_url", *openclawURL,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	agent := NewAgent(AgentConfig{
		Transport:  *transportFlag,
		Port:       uint32(*portFlag),
		OpenClawURL: *openclawURL,
	})

	return agent.Run(ctx)
}
```

**Step 2: Verify it compiles**

Run: `go build ./cmd/valinor-agent`
Expected: FAIL — `NewAgent` and `AgentConfig` not defined (yet — we build them in the next task)

**Step 3: Commit (scaffold only)**

We'll commit this in the next task once Agent struct exists.

---

### Task 12: In-Guest Agent — Core Agent Loop

**Files:**
- Create: `cmd/valinor-agent/agent.go`
- Create: `cmd/valinor-agent/agent_test.go`

**Step 1: Write the failing test**

Create `cmd/valinor-agent/agent_test.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestAgent_PingPong(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	agent := &Agent{
		cfg: AgentConfig{OpenClawURL: "http://localhost:8081"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run agent loop in background
	go agent.handleConnection(ctx, server)

	// Send ping from control plane side
	cp := proxy.NewAgentConn(client)
	ping := proxy.Frame{
		Type:    proxy.TypePing,
		ID:      "ping-1",
		Payload: json.RawMessage(`{}`),
	}
	err := cp.Send(ctx, ping)
	require.NoError(t, err)

	// Should get heartbeat first (sent on connect), then pong
	// Read frames until we get a pong
	for {
		reply, err := cp.Recv(ctx)
		require.NoError(t, err)
		if reply.Type == proxy.TypePong {
			assert.Equal(t, "ping-1", reply.ID)
			return
		}
		// Skip heartbeats
		assert.Equal(t, proxy.TypeHeartbeat, reply.Type)
	}
}

func TestAgent_ConfigUpdate(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	agent := &Agent{
		cfg: AgentConfig{OpenClawURL: "http://localhost:8081"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	// Skip initial heartbeat
	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	// Send config update
	configPayload := json.RawMessage(`{"config":{"model":"gpt-4o"},"tool_allowlist":["search"]}`)
	configFrame := proxy.Frame{
		Type:    proxy.TypeConfigUpdate,
		ID:      "cfg-1",
		Payload: configPayload,
	}
	err = cp.Send(ctx, configFrame)
	require.NoError(t, err)

	// Should get config_ack
	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeConfigAck, reply.Type)
	assert.Equal(t, "cfg-1", reply.ID)

	// Verify allow-list was applied
	assert.Equal(t, []string{"search"}, agent.toolAllowlist)
}

func TestAgent_ToolAllowList(t *testing.T) {
	agent := &Agent{
		toolAllowlist: []string{"search_players", "get_report"},
	}

	assert.True(t, agent.isToolAllowed("search_players"))
	assert.True(t, agent.isToolAllowed("get_report"))
	assert.False(t, agent.isToolAllowed("delete_all"))

	// Empty list = all allowed
	agent.toolAllowlist = nil
	assert.True(t, agent.isToolAllowed("anything"))
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/valinor-agent/... -v -run TestAgent`
Expected: FAIL — `Agent`, `AgentConfig`, `handleConnection`, `isToolAllowed` not defined

**Step 3: Write minimal implementation**

Create `cmd/valinor-agent/agent.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/valinor-ai/valinor/internal/proxy"
)

// AgentConfig holds in-guest agent configuration.
type AgentConfig struct {
	Transport   string
	Port        uint32
	OpenClawURL string
}

// Agent is the in-guest valinor-agent that bridges the control plane to OpenClaw.
type Agent struct {
	cfg           AgentConfig
	toolAllowlist []string
	mu            sync.RWMutex // protects toolAllowlist and config
	config        map[string]any
}

// NewAgent creates a new Agent.
func NewAgent(cfg AgentConfig) *Agent {
	return &Agent{cfg: cfg}
}

// Run starts the agent: listens for control plane connections.
func (a *Agent) Run(ctx context.Context) error {
	var transport proxy.Transport
	switch a.cfg.Transport {
	case "tcp":
		transport = proxy.NewTCPTransport(0) // port is the full port for TCP agent mode
	default:
		// vsock transport would be used in production (Linux only)
		// For now, default to TCP for development
		transport = proxy.NewTCPTransport(0)
	}

	ln, err := transport.Listen(ctx, a.cfg.Port)
	if err != nil {
		return fmt.Errorf("listening on port %d: %w", a.cfg.Port, err)
	}
	defer ln.Close()

	slog.Info("agent listening", "port", a.cfg.Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			slog.Error("accept failed", "error", err)
			continue
		}

		go a.handleConnection(ctx, conn)
	}
}

// handleConnection processes frames from a single control plane connection.
func (a *Agent) handleConnection(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	conn := proxy.NewAgentConn(raw)

	// Send initial heartbeat
	hb := proxy.Frame{
		Type:    proxy.TypeHeartbeat,
		ID:      "",
		Payload: json.RawMessage(`{"status":"ready","uptime_secs":0}`),
	}
	if err := conn.Send(ctx, hb); err != nil {
		slog.Error("initial heartbeat failed", "error", err)
		return
	}

	// Start heartbeat goroutine
	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
	defer heartbeatCancel()
	go a.heartbeatLoop(heartbeatCtx, conn)

	// Main frame dispatch loop
	for {
		if ctx.Err() != nil {
			return
		}

		frame, err := conn.Recv(ctx)
		if err != nil {
			slog.Info("connection closed", "error", err)
			return
		}

		switch frame.Type {
		case proxy.TypeConfigUpdate:
			a.handleConfigUpdate(ctx, conn, frame)
		case proxy.TypeMessage:
			go a.handleMessage(ctx, conn, frame)
		case proxy.TypeContextUpdate:
			a.handleContextUpdate(ctx, conn, frame)
		case proxy.TypePing:
			pong := proxy.Frame{
				Type:    proxy.TypePong,
				ID:      frame.ID,
				Payload: json.RawMessage(`{}`),
			}
			if err := conn.Send(ctx, pong); err != nil {
				slog.Error("pong send failed", "error", err)
				return
			}
		default:
			slog.Warn("unknown frame type", "type", frame.Type)
		}
	}
}

func (a *Agent) handleConfigUpdate(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	var payload struct {
		Config        map[string]any `json:"config"`
		ToolAllowlist []string       `json:"tool_allowlist"`
	}
	if err := json.Unmarshal(frame.Payload, &payload); err != nil {
		slog.Error("invalid config payload", "error", err)
		errFrame := proxy.Frame{
			Type:    proxy.TypeError,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"code":"invalid_payload","message":"invalid config payload"}`),
		}
		_ = conn.Send(ctx, errFrame)
		return
	}

	a.mu.Lock()
	a.config = payload.Config
	a.toolAllowlist = payload.ToolAllowlist
	a.mu.Unlock()

	slog.Info("config updated", "tools", len(payload.ToolAllowlist))

	ack := proxy.Frame{
		Type:    proxy.TypeConfigAck,
		ID:      frame.ID,
		Payload: json.RawMessage(`{"applied":true}`),
	}
	if err := conn.Send(ctx, ack); err != nil {
		slog.Error("config ack failed", "error", err)
	}
}

func (a *Agent) handleMessage(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	// TODO: Forward to OpenClaw at a.cfg.OpenClawURL
	// For now, echo back as a single done chunk
	reply := proxy.Frame{
		Type:    proxy.TypeChunk,
		ID:      frame.ID,
		Payload: json.RawMessage(`{"content":"[agent echo] message received","done":true}`),
	}
	if err := conn.Send(ctx, reply); err != nil {
		slog.Error("message reply failed", "error", err)
	}
}

func (a *Agent) handleContextUpdate(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	// TODO: Forward context to OpenClaw memory
	slog.Info("context update received")

	ack := proxy.Frame{
		Type:    proxy.TypeConfigAck,
		ID:      frame.ID,
		Payload: json.RawMessage(`{"applied":true}`),
	}
	if err := conn.Send(ctx, ack); err != nil {
		slog.Error("context ack failed", "error", err)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context, conn *proxy.AgentConn) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			uptime := int(time.Since(startTime).Seconds())
			payload := fmt.Sprintf(`{"status":"running","uptime_secs":%d}`, uptime)
			hb := proxy.Frame{
				Type:    proxy.TypeHeartbeat,
				ID:      "",
				Payload: json.RawMessage(payload),
			}
			if err := conn.Send(ctx, hb); err != nil {
				slog.Error("heartbeat failed", "error", err)
				return
			}
		}
	}
}

// isToolAllowed checks if a tool is in the allow-list.
func (a *Agent) isToolAllowed(toolName string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.toolAllowlist) == 0 {
		return true // empty list = all allowed
	}
	return slices.Contains(a.toolAllowlist, toolName)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/valinor-agent/... -v -count=1`
Expected: PASS (all 3 tests)

**Step 5: Verify binary compiles**

Run: `go build ./cmd/valinor-agent`
Expected: SUCCESS

**Step 6: Commit**

```bash
git add cmd/valinor-agent/main.go cmd/valinor-agent/agent.go cmd/valinor-agent/agent_test.go
git commit -m "feat(agent): add in-guest valinor-agent binary with core loop"
```

---

### Task 13: In-Guest Agent — OpenClaw HTTP Proxy

**Files:**
- Create: `cmd/valinor-agent/openclaw.go`
- Create: `cmd/valinor-agent/openclaw_test.go`

**Step 1: Write the failing test**

Create `cmd/valinor-agent/openclaw_test.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestOpenClawProxy_Message(t *testing.T) {
	// Mock OpenClaw HTTP server
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)

		// Return a simple non-streaming response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "The answer is 42"}},
			},
		})
	}))
	defer mockOpenClaw.Close()

	agent := &Agent{
		cfg: AgentConfig{OpenClawURL: mockOpenClaw.URL},
	}

	// Use net.Pipe for the vsock side
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run agent connection handler
	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	// Skip initial heartbeat
	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	// Send message
	msg := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "msg-1",
		Payload: json.RawMessage(`{"role":"user","content":"What is the meaning of life?"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	// Should receive a done chunk
	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeChunk, reply.Type)

	var chunk struct {
		Content string `json:"content"`
		Done    bool   `json:"done"`
	}
	err = json.Unmarshal(reply.Payload, &chunk)
	require.NoError(t, err)
	assert.Contains(t, chunk.Content, "42")
	assert.True(t, chunk.Done)
}

func TestOpenClawProxy_ToolBlocked(t *testing.T) {
	// Mock OpenClaw that returns a tool call
	mockOpenClaw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"tool_calls": []map[string]any{
							{
								"function": map[string]string{
									"name":      "delete_all_data",
									"arguments": "{}",
								},
							},
						},
					},
				},
			},
		})
	}))
	defer mockOpenClaw.Close()

	agent := &Agent{
		cfg:           AgentConfig{OpenClawURL: mockOpenClaw.URL},
		toolAllowlist: []string{"search_players"}, // delete_all_data is NOT allowed
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go agent.handleConnection(ctx, server)

	cp := proxy.NewAgentConn(client)

	// Skip initial heartbeat
	_, err := cp.Recv(ctx)
	require.NoError(t, err)

	msg := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "msg-2",
		Payload: json.RawMessage(`{"role":"user","content":"delete everything"}`),
	}
	err = cp.Send(ctx, msg)
	require.NoError(t, err)

	reply, err := cp.Recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeToolBlocked, reply.Type)

	var blocked struct {
		ToolName string `json:"tool_name"`
		Reason   string `json:"reason"`
	}
	err = json.Unmarshal(reply.Payload, &blocked)
	require.NoError(t, err)
	assert.Equal(t, "delete_all_data", blocked.ToolName)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/valinor-agent/... -v -run TestOpenClaw`
Expected: FAIL — the existing `handleMessage` is a stub that echoes

**Step 3: Write implementation**

Create `cmd/valinor-agent/openclaw.go`:

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/valinor-ai/valinor/internal/proxy"
)

// openClawResponse models the OpenClaw chat completions response.
type openClawResponse struct {
	Choices []struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// forwardToOpenClaw sends a message to OpenClaw and returns response frames.
func (a *Agent) forwardToOpenClaw(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	var msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(frame.Payload, &msg); err != nil {
		a.sendError(ctx, conn, frame.ID, "invalid_message", "invalid message payload")
		return
	}

	// Build OpenClaw request
	reqBody := map[string]any{
		"messages": []map[string]string{
			{"role": msg.Role, "content": msg.Content},
		},
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "marshal_error", "failed to marshal request")
		return
	}

	url := fmt.Sprintf("%s/v1/chat/completions", a.cfg.OpenClawURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "request_error", "failed to create request")
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "openclaw_error", fmt.Sprintf("OpenClaw request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		a.sendError(ctx, conn, frame.ID, "read_error", "failed to read OpenClaw response")
		return
	}

	if resp.StatusCode != http.StatusOK {
		a.sendError(ctx, conn, frame.ID, "openclaw_error", fmt.Sprintf("OpenClaw returned %d", resp.StatusCode))
		return
	}

	var ocResp openClawResponse
	if err := json.Unmarshal(respBody, &ocResp); err != nil {
		a.sendError(ctx, conn, frame.ID, "parse_error", "failed to parse OpenClaw response")
		return
	}

	if len(ocResp.Choices) == 0 {
		a.sendError(ctx, conn, frame.ID, "empty_response", "OpenClaw returned no choices")
		return
	}

	choice := ocResp.Choices[0]

	// Check for tool calls
	if len(choice.Message.ToolCalls) > 0 {
		for _, tc := range choice.Message.ToolCalls {
			if !a.isToolAllowed(tc.Function.Name) {
				blocked := proxy.Frame{
					Type: proxy.TypeToolBlocked,
					ID:   frame.ID,
					Payload: mustMarshal(map[string]string{
						"tool_name": tc.Function.Name,
						"reason":    "tool not in allow-list",
					}),
				}
				if err := conn.Send(ctx, blocked); err != nil {
					slog.Error("tool_blocked send failed", "error", err)
				}
				return
			}
		}
		// All tools allowed — in a full implementation, we'd execute them
		// For MVP, send the content back
	}

	// Send content as done chunk
	content := choice.Message.Content
	chunk := proxy.Frame{
		Type: proxy.TypeChunk,
		ID:   frame.ID,
		Payload: mustMarshal(map[string]any{
			"content": content,
			"done":    true,
		}),
	}
	if err := conn.Send(ctx, chunk); err != nil {
		slog.Error("chunk send failed", "error", err)
	}
}

func (a *Agent) sendError(ctx context.Context, conn *proxy.AgentConn, reqID, code, message string) {
	slog.Error("agent error", "code", code, "message", message)
	errFrame := proxy.Frame{
		Type: proxy.TypeError,
		ID:   reqID,
		Payload: mustMarshal(map[string]string{
			"code":    code,
			"message": message,
		}),
	}
	_ = conn.Send(ctx, errFrame)
}

func mustMarshal(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustMarshal: %v", err))
	}
	return data
}
```

Now update `agent.go` to use the real `forwardToOpenClaw` instead of the stub:

Replace the `handleMessage` method in `cmd/valinor-agent/agent.go`:

```go
func (a *Agent) handleMessage(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
	a.forwardToOpenClaw(ctx, conn, frame)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/valinor-agent/... -v -count=1`
Expected: PASS (all tests including OpenClaw proxy tests)

**Step 5: Commit**

```bash
git add cmd/valinor-agent/openclaw.go cmd/valinor-agent/openclaw_test.go cmd/valinor-agent/agent.go
git commit -m "feat(agent): add OpenClaw HTTP proxy with tool allow-list enforcement"
```

---

### Task 14: Server Wiring — Register Proxy Routes and Wire Dependencies

**Files:**
- Modify: `internal/platform/server/server.go` (add ProxyHandler to Dependencies, register routes)
- Modify: `cmd/valinor/main.go` (create proxy handler, pass to server)

**Step 1: Add ProxyHandler to Dependencies**

In `internal/platform/server/server.go`, add to Dependencies struct:

```go
type Dependencies struct {
	Pool              *pgxpool.Pool
	Auth              *auth.TokenService
	AuthHandler       *auth.Handler
	RBAC              *rbac.Evaluator
	TenantHandler     *tenant.Handler
	DepartmentHandler *tenant.DepartmentHandler
	UserHandler       *tenant.UserHandler
	RoleHandler       *tenant.RoleHandler
	AgentHandler      *orchestrator.Handler
	ProxyHandler      *proxy.Handler  // NEW
	DevMode           bool
	DevIdentity       *auth.Identity
	Logger            *slog.Logger
}
```

Add import for `proxy` package, and add route registration block after agent routes:

```go
// Proxy routes (agent messaging)
if deps.ProxyHandler != nil && deps.RBAC != nil {
	protectedMux.Handle("POST /api/v1/agents/{id}/message",
		rbac.RequirePermission(deps.RBAC, "agents:write")(
			http.HandlerFunc(deps.ProxyHandler.HandleMessage),
		),
	)
	protectedMux.Handle("GET /api/v1/agents/{id}/stream",
		rbac.RequirePermission(deps.RBAC, "agents:write")(
			http.HandlerFunc(deps.ProxyHandler.HandleStream),
		),
	)
	protectedMux.Handle("POST /api/v1/agents/{id}/context",
		rbac.RequirePermission(deps.RBAC, "agents:write")(
			http.HandlerFunc(deps.ProxyHandler.HandleContext),
		),
	)
}
```

**Step 2: Wire in main.go**

In `cmd/valinor/main.go`, after the orchestrator block, add proxy wiring:

```go
// Proxy — agent messaging and config push
var proxyHandler *proxy.Handler
var connPool *proxy.ConnPool
if pool != nil {
	transport := proxy.NewTCPTransport(cfg.Proxy.TCPBasePort)
	connPool = proxy.NewConnPool(transport)

	proxyHandler = proxy.NewHandler(connPool, orchManager, proxy.HandlerConfig{
		MessageTimeout: time.Duration(cfg.Proxy.MessageTimeout) * time.Second,
		ConfigTimeout:  time.Duration(cfg.Proxy.ConfigTimeout) * time.Second,
		PingTimeout:    time.Duration(cfg.Proxy.PingTimeout) * time.Second,
	})
}
```

Also wire the ConfigPusher into the orchestrator handler. Create a small adapter:

```go
// configPusherAdapter wraps proxy.ConnPool to implement orchestrator.ConfigPusher.
type configPusherAdapter struct {
	pool    *proxy.ConnPool
	timeout time.Duration
}

func (a *configPusherAdapter) PushConfig(ctx context.Context, agentID string, cid uint32, config map[string]any, toolAllowlist []string) error {
	return proxy.PushConfig(ctx, a.pool, agentID, cid, config, toolAllowlist, a.timeout)
}
```

Update orchestrator handler creation:

```go
var pusher orchestrator.ConfigPusher
if connPool != nil {
	pusher = &configPusherAdapter{
		pool:    connPool,
		timeout: time.Duration(cfg.Proxy.ConfigTimeout) * time.Second,
	}
}
agentHandler = orchestrator.NewHandler(orchManager, pusher)
```

Update the Dependencies struct usage:

```go
srv := server.New(addr, server.Dependencies{
	// ... existing fields ...
	ProxyHandler: proxyHandler,
})
```

Add cleanup for ConnPool:

```go
if connPool != nil {
	defer connPool.Close()
}
```

Add import for proxy package.

**Step 3: Verify compile**

Run: `go build ./cmd/valinor`
Expected: SUCCESS

**Step 4: Run all tests**

Run: `go test ./... -short -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/platform/server/server.go cmd/valinor/main.go
git commit -m "feat: wire proxy handler into server routes and main.go"
```

---

### Task 15: Increase Server WriteTimeout for SSE

**Files:**
- Modify: `internal/platform/server/server.go` (increase WriteTimeout or disable for SSE)

SSE streams can last indefinitely. The current 15s WriteTimeout will kill long streams.

**Step 1: Adjust timeout**

The simplest approach: set WriteTimeout to 0 (no timeout) since SSE controls its own lifecycle via context cancellation. Alternatively, increase to a generous value like 5 minutes.

In `internal/platform/server/server.go`, change:

```go
WriteTimeout: 0, // SSE streams have no server-side timeout; client disconnects end them
```

**Step 2: Verify compile and tests**

Run: `go build ./cmd/valinor && go test ./... -short -count=1`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/platform/server/server.go
git commit -m "fix(server): disable WriteTimeout for SSE streaming support"
```

---

### Task 16: End-to-End Integration Test

**Files:**
- Create: `internal/proxy/integration_test.go`

This test starts a mock valinor-agent on TCP, creates a proxy handler, sends a message, and verifies the full round-trip.

**Step 1: Write integration test**

Create `internal/proxy/integration_test.go`:

```go
package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestEndToEnd_MessageRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	transport := proxy.NewTCPTransport(9900)
	pool := proxy.NewConnPool(transport)
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cid := uint32(5)
	agentID := "e2e-agent"
	tenantID := "e2e-tenant"

	// Start a realistic mock agent
	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	go runMockAgent(t, ctx, ln)

	store := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID: {
				ID:       agentID,
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusRunning,
			},
		},
	}

	handler := proxy.NewHandler(pool, store, proxy.HandlerConfig{
		MessageTimeout: 10 * time.Second,
	})

	// Test 1: POST /message — full response
	body := `{"role":"user","content":"What is 2+2?"}`
	req := httptest.NewRequest("POST", "/agents/"+agentID+"/message", bytes.NewBufferString(body))
	req.SetPathValue("id", agentID)
	w := httptest.NewRecorder()

	handler.HandleMessage(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["content"], "4")

	// Test 2: GET /stream — SSE
	pool.Remove(agentID) // force new connection for second test

	// Start another agent listener for the same CID
	ln2, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln2.Close()

	go runStreamingMockAgent(t, ctx, ln2)

	req2 := httptest.NewRequest("GET", "/agents/"+agentID+"/stream?message="+`{"role":"user","content":"stream test"}`, nil)
	req2.SetPathValue("id", agentID)
	w2 := httptest.NewRecorder()

	handler.HandleStream(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "text/event-stream", w2.Header().Get("Content-Type"))
	assert.Contains(t, w2.Body.String(), "event: chunk")
	assert.Contains(t, w2.Body.String(), "event: done")
}

// runMockAgent simulates a valinor-agent that replies to messages.
func runMockAgent(t *testing.T, ctx context.Context, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	ac := proxy.NewAgentConn(conn)

	for {
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		switch frame.Type {
		case proxy.TypeMessage:
			reply := proxy.Frame{
				Type:    proxy.TypeChunk,
				ID:      frame.ID,
				Payload: json.RawMessage(`{"content":"The answer is 4","done":true}`),
			}
			if err := ac.Send(ctx, reply); err != nil {
				return
			}
		case proxy.TypePing:
			pong := proxy.Frame{
				Type:    proxy.TypePong,
				ID:      frame.ID,
				Payload: json.RawMessage(`{}`),
			}
			_ = ac.Send(ctx, pong)
		}
	}
}

// runStreamingMockAgent sends two chunks for any message.
func runStreamingMockAgent(t *testing.T, ctx context.Context, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	ac := proxy.NewAgentConn(conn)

	for {
		frame, err := ac.Recv(ctx)
		if err != nil {
			return
		}

		if frame.Type == proxy.TypeMessage {
			chunk1 := proxy.Frame{
				Type:    proxy.TypeChunk,
				ID:      frame.ID,
				Payload: json.RawMessage(`{"content":"Streaming ","done":false}`),
			}
			_ = ac.Send(ctx, chunk1)

			chunk2 := proxy.Frame{
				Type:    proxy.TypeChunk,
				ID:      frame.ID,
				Payload: json.RawMessage(fmt.Sprintf(`{"content":"response","done":true}`)),
			}
			_ = ac.Send(ctx, chunk2)
		}
	}
}
```

**Step 2: Run integration test**

Run: `go test ./internal/proxy/... -v -run TestEndToEnd -count=1`
Expected: PASS

**Step 3: Run all tests**

Run: `go test ./... -short -count=1`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/proxy/integration_test.go
git commit -m "test: add end-to-end integration test for proxy + mock agent"
```

---

### Task 17: Clean Up — Remove .gitkeep Files, Final Verification

**Files:**
- Delete: `internal/proxy/.gitkeep`
- Delete: `valinor-agent/.gitkeep` (the old placeholder — code now lives in `cmd/valinor-agent/`)

**Step 1: Remove placeholders**

```bash
rm internal/proxy/.gitkeep
rm valinor-agent/.gitkeep
```

Note: If `valinor-agent/` is expected to hold agent code per the original plan, leave it. But per our implementation, the agent binary is at `cmd/valinor-agent/`, so the top-level `valinor-agent/` dir is now unused.

**Step 2: Full test suite**

Run: `go test ./... -short -count=1`
Expected: PASS

Run: `go build ./cmd/valinor && go build ./cmd/valinor-agent`
Expected: Both compile successfully

**Step 3: Commit**

```bash
git rm internal/proxy/.gitkeep valinor-agent/.gitkeep
git commit -m "chore: remove placeholder .gitkeep files replaced by actual code"
```

---

## Summary

| Task | Component | Files |
|------|-----------|-------|
| 1 | Wire Protocol (Frame types, encode/decode) | `internal/proxy/protocol.go`, `protocol_test.go` |
| 2 | Transport Interface + TCPTransport | `internal/proxy/transport.go`, `transport_test.go` |
| 3 | AgentConn (Send/Recv) | `internal/proxy/conn.go`, `conn_test.go` |
| 4 | ConnPool (lazy connection pooling) | `internal/proxy/pool.go`, `pool_test.go` |
| 5 | ProxyConfig in config struct | `internal/platform/config/config.go` |
| 6 | HandleMessage endpoint | `internal/proxy/handler.go`, `handler_test.go` |
| 7 | HandleStream SSE endpoint | `internal/proxy/handler.go`, `handler_test.go` |
| 8 | HandleContext endpoint | `internal/proxy/handler.go`, `handler_test.go` |
| 9 | PushConfig function | `internal/proxy/push.go`, `push_test.go` |
| 10 | ConfigPusher integration | `internal/orchestrator/handler.go`, `cmd/valinor/main.go` |
| 11-12 | In-guest agent binary + core loop | `cmd/valinor-agent/main.go`, `agent.go`, `agent_test.go` |
| 13 | OpenClaw HTTP proxy + tool allow-list | `cmd/valinor-agent/openclaw.go`, `openclaw_test.go` |
| 14 | Server wiring + main.go composition | `internal/platform/server/server.go`, `cmd/valinor/main.go` |
| 15 | SSE timeout fix | `internal/platform/server/server.go` |
| 16 | End-to-end integration test | `internal/proxy/integration_test.go` |
| 17 | Cleanup + final verification | Remove `.gitkeep` files |
