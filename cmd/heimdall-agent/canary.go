package main

import "strings"

// checkCanary scans content for any canary token. Returns (found, token).
func (a *Agent) checkCanary(content string) (bool, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, token := range a.canaryTokens {
		if strings.Contains(content, token) {
			return true, token
		}
	}
	return false, ""
}
