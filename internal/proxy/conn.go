package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
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
func (c *AgentConn) Recv(ctx context.Context) (Frame, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Set deadline from context if available
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
		defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	}

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
