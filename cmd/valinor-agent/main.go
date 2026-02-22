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
		Transport:   *transportFlag,
		Port:        uint32(*portFlag),
		OpenClawURL: *openclawURL,
	})

	return agent.Run(ctx)
}
