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

	if *portFlag < 0 || *portFlag > 65535 {
		return fmt.Errorf("port must be between 0 and 65535, got %d", *portFlag)
	}

	agent := NewAgent(AgentConfig{
		Transport:   *transportFlag,
		Port:        uint32(*portFlag), // #nosec G115 -- bounds checked above
		OpenClawURL: *openclawURL,
	})

	return agent.Run(ctx)
}
