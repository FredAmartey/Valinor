package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const subprocessStopTimeout = 5 * time.Second

// Subprocess manages a child process lifecycle.
type Subprocess struct {
	Name      string
	Args      []string
	Env       []string
	Dir       string
	ReadyURL  string        // HTTP URL to poll for readiness
	ReadyWait time.Duration // max time to wait for readiness

	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool
	done    chan struct{} // closed when cmd.Wait() returns
}

// Start launches the subprocess.
func (s *Subprocess) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// #nosec G204 -- Name and Args are set by agent code (hardcoded "openclaw"), not user input.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	s.cmd = exec.CommandContext(ctx, s.Name, s.Args...)
	s.cmd.Env = append(os.Environ(), s.Env...)
	if s.Dir != "" {
		s.cmd.Dir = s.Dir
	}
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", s.Name, err)
	}

	s.running = true
	s.done = make(chan struct{})
	slog.Info("subprocess started", "name", s.Name, "pid", s.cmd.Process.Pid)

	go func() {
		_ = s.cmd.Wait()
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		close(s.done)
		slog.Info("subprocess exited", "name", s.Name)
	}()

	return nil
}

// WaitForReady polls the ReadyURL until it responds or the context expires.
func (s *Subprocess) WaitForReady(ctx context.Context) error {
	if s.ReadyURL == "" {
		return nil
	}

	deadline := s.ReadyWait
	if deadline <= 0 {
		deadline = 10 * time.Second
	}

	waitCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	httpClient := &http.Client{Timeout: 1 * time.Second}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("subprocess %s not ready after %s: %w", s.Name, deadline, waitCtx.Err())
		case <-ticker.C:
			req, err := http.NewRequestWithContext(waitCtx, http.MethodGet, s.ReadyURL, nil)
			if err != nil {
				continue
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close() // #nosec G104 -- best-effort close in readiness poll
			if resp.StatusCode < 500 {
				slog.Info("subprocess ready", "name", s.Name, "url", s.ReadyURL)
				return nil
			}
		}
	}
}

// Stop sends SIGTERM to the process group, waits for exit, then SIGKILL if needed.
// The context controls the maximum time to wait for graceful shutdown.
func (s *Subprocess) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running || s.cmd == nil || s.cmd.Process == nil {
		s.mu.Unlock()
		return nil
	}
	pid := s.cmd.Process.Pid
	done := s.done
	s.mu.Unlock()

	// Send SIGTERM to process group.
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		slog.Warn("SIGTERM failed, sending SIGKILL", "name", s.Name, "error", err)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}

	// Wait for process to exit, context cancellation, or timeout.
	select {
	case <-done:
		// Process exited cleanly.
	case <-ctx.Done():
		slog.Warn("stop context expired, sending SIGKILL", "name", s.Name)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-done
	case <-time.After(subprocessStopTimeout):
		slog.Warn("subprocess did not exit after SIGTERM, sending SIGKILL", "name", s.Name)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-done
	}

	return nil
}

// Running returns whether the subprocess is still running.
func (s *Subprocess) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
