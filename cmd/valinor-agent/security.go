package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateOpenClawURL enforces safe endpoint defaults for the in-guest bridge.
// By default, only loopback hosts are allowed. allowRemote is an explicit break-glass override.
func validateOpenClawURL(raw string, allowRemote bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("openclaw url is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid openclaw url: %w", err)
	}
	if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("openclaw url must include scheme and host")
	}

	if allowRemote {
		return nil
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("openclaw url host is required")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}

	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return nil
	}

	return fmt.Errorf("openclaw url must use a loopback host unless allow-remote-openclaw is enabled (got %q)", host)
}
