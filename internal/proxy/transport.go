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
