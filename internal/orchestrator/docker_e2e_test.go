package orchestrator_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/FredAmartey/heimdall/internal/orchestrator"
	"github.com/FredAmartey/heimdall/internal/proxy"
)

// requireDockerImage skips the test if Docker daemon is not available
// or the specified image has not been built.
func requireDockerImage(t *testing.T, image string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Docker E2E test in short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not found, skipping")
	}
	if err := exec.CommandContext(context.Background(), "docker", "info").Run(); err != nil {
		t.Skip("Docker daemon not running, skipping")
	}
	if err := exec.CommandContext(context.Background(), "docker", "image", "inspect", image).Run(); err != nil {
		t.Skipf("Docker image %s not found (build with: docker build -f Dockerfile.agent -t %s .), skipping", image, image)
	}
}

// TestDockerDriver_E2E tests the full flow: start container, connect via proxy, send ping, verify pong.
// Requires Docker daemon and heimdall/agent:dev image built.
func TestDockerDriver_E2E(t *testing.T) {
	const agentImage = "heimdall/agent:dev"
	requireDockerImage(t, agentImage)

	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           agentImage,
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 256,
		Cmd:             []string{"--skip-openclaw-spawn"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	spec := orchestrator.VMSpec{
		VMID:     "test-e2e",
		VsockCID: 500,
	}

	// Start container
	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	defer func() {
		_ = driver.Stop(ctx, spec.VMID)
		_ = driver.Cleanup(ctx, spec.VMID)
	}()

	// Wait for agent to start listening inside the container.
	// The agent needs a moment to bind its TCP port.
	time.Sleep(3 * time.Second)

	// Connect via TCP transport (basePort 9100 matches dockerAgentPort).
	// Dial CID 500 → 127.0.0.1:9600 which is the host-mapped port.
	transport := proxy.NewTCPTransport(9100)
	conn, err := transport.Dial(ctx, handle.VsockCID)
	require.NoError(t, err)
	defer conn.Close()

	agentConn := proxy.NewAgentConn(conn)

	// The agent sends an initial heartbeat upon connection.
	frame, err := agentConn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.TypeHeartbeat, frame.Type)

	// Send ping
	pingFrame := proxy.Frame{
		Type:    proxy.TypePing,
		ID:      "e2e-ping-1",
		Payload: json.RawMessage(`{}`),
	}
	err = agentConn.Send(ctx, pingFrame)
	require.NoError(t, err)

	// Receive pong (may be interleaved with periodic heartbeats).
	for {
		resp, err := agentConn.Recv(ctx)
		require.NoError(t, err)
		if resp.Type == proxy.TypeHeartbeat {
			continue // skip periodic heartbeats
		}
		require.Equal(t, proxy.TypePong, resp.Type)
		require.Equal(t, "e2e-ping-1", resp.ID)
		break
	}
}
