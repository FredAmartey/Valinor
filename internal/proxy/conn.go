package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// AgentConn wraps a net.Conn with the length-prefixed JSON protocol.
type AgentConn struct {
	conn   net.Conn
	mu     sync.Mutex // serializes writes
	readMu sync.Mutex // serializes reads

	pendingMu       sync.Mutex
	pending         map[string]*RequestStream
	requestModeOn   bool
	requestLoopErr  error
	requestLoopOnce sync.Once
}

// RequestStream receives response frames for one in-flight request ID.
type RequestStream struct {
	conn   *AgentConn
	id     string
	frames chan Frame
	closed chan struct{}
	once   sync.Once
}

// NewAgentConn wraps a raw connection with frame send/recv capabilities.
func NewAgentConn(conn net.Conn) *AgentConn {
	return &AgentConn{
		conn:    conn,
		pending: make(map[string]*RequestStream),
	}
}

// Send writes a length-prefixed Frame to the connection.
func (c *AgentConn) Send(ctx context.Context, frame Frame) error {
	data, err := EncodeFrame(frame)
	if err != nil {
		return fmt.Errorf("encoding frame: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(deadline)
		defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	}

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("writing frame: %w", err)
	}
	return nil
}

// Recv reads a length-prefixed Frame from the connection.
func (c *AgentConn) Recv(ctx context.Context) (Frame, error) {
	if c.isRequestModeEnabled() {
		return Frame{}, errors.New("Recv cannot be used after SendRequest; use request stream Recv")
	}
	return c.recvFrame(ctx)
}

// SendRequest sends a frame and returns a request stream scoped to frame ID.
func (c *AgentConn) SendRequest(ctx context.Context, frame Frame) (*RequestStream, error) {
	if c == nil {
		return nil, errors.New("agent connection is nil")
	}
	frameID := strings.TrimSpace(frame.ID)
	if frameID == "" {
		return nil, errors.New("frame id is required")
	}
	frame.ID = frameID

	c.startRequestLoop()

	request, err := c.registerRequest(frameID)
	if err != nil {
		return nil, err
	}

	if err := c.Send(ctx, frame); err != nil {
		request.Close()
		return nil, err
	}
	return request, nil
}

// Recv waits for the next response frame for this request stream.
func (r *RequestStream) Recv(ctx context.Context) (Frame, error) {
	if r == nil {
		return Frame{}, errors.New("request stream is nil")
	}

	select {
	case frame, ok := <-r.frames:
		if ok {
			return frame, nil
		}
		return Frame{}, r.conn.getRequestLoopErr()
	case <-r.closed:
		return Frame{}, errors.New("request stream closed")
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	}
}

// Close unregisters this request stream.
func (r *RequestStream) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		close(r.closed)
		if r.conn != nil {
			r.conn.unregisterRequest(r.id, r)
		}
	})
}

func (c *AgentConn) startRequestLoop() {
	c.requestLoopOnce.Do(func() {
		c.pendingMu.Lock()
		c.requestModeOn = true
		c.pendingMu.Unlock()
		go c.runRequestLoop()
	})
}

func (c *AgentConn) runRequestLoop() {
	for {
		frame, err := c.recvFrame(context.Background())
		if err != nil {
			c.failAllRequests(fmt.Errorf("request recv loop failed: %w", err))
			return
		}
		c.dispatchRequestFrame(frame)
	}
}

func (c *AgentConn) dispatchRequestFrame(frame Frame) {
	c.pendingMu.Lock()
	request := c.pending[frame.ID]
	c.pendingMu.Unlock()

	if request == nil {
		return
	}

	select {
	case request.frames <- frame:
	case <-request.closed:
		c.unregisterRequest(frame.ID, request)
	}
}

func (c *AgentConn) registerRequest(frameID string) (*RequestStream, error) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()

	if c.requestLoopErr != nil {
		return nil, c.requestLoopErr
	}
	if _, exists := c.pending[frameID]; exists {
		return nil, fmt.Errorf("request %s is already in flight", frameID)
	}

	request := &RequestStream{
		conn:   c,
		id:     frameID,
		frames: make(chan Frame, 16),
		closed: make(chan struct{}),
	}
	c.pending[frameID] = request
	return request, nil
}

func (c *AgentConn) unregisterRequest(frameID string, request *RequestStream) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()

	current, exists := c.pending[frameID]
	if !exists {
		return
	}
	if request != nil && current != request {
		return
	}
	delete(c.pending, frameID)
}

func (c *AgentConn) failAllRequests(err error) {
	c.pendingMu.Lock()
	if c.requestLoopErr == nil {
		if err != nil {
			c.requestLoopErr = err
		} else {
			c.requestLoopErr = errors.New("request recv loop stopped")
		}
	}
	pending := c.pending
	c.pending = make(map[string]*RequestStream)
	c.pendingMu.Unlock()

	for _, request := range pending {
		close(request.frames)
	}
}

func (c *AgentConn) getRequestLoopErr() error {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if c.requestLoopErr != nil {
		return c.requestLoopErr
	}
	return errors.New("request recv loop stopped")
}

func (c *AgentConn) isRequestModeEnabled() bool {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	return c.requestModeOn
}

func (c *AgentConn) recvFrame(ctx context.Context) (Frame, error) {
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
	err := c.conn.Close()
	c.failAllRequests(errors.New("connection closed"))
	return err
}
