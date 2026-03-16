package main

import (
	"encoding/json"
	"fmt"
	"slices"
)

// ValidationResult is the outcome of a tool call validation.
type ValidationResult struct {
	Allowed bool
	Reason  string
}

// validateToolCall checks tool name against the allow-list and parameters against the policy.
func (a *Agent) validateToolCall(toolName string, arguments string) ValidationResult {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check allow-list
	if len(a.toolAllowlist) > 0 && !slices.Contains(a.toolAllowlist, toolName) {
		return ValidationResult{
			Allowed: false,
			Reason:  fmt.Sprintf("tool %q not in allow-list", toolName),
		}
	}

	// Check parameter policy
	if a.toolPolicies == nil {
		return ValidationResult{Allowed: true}
	}

	policy, hasPolicy := a.toolPolicies[toolName]
	if !hasPolicy {
		return ValidationResult{Allowed: true}
	}

	// Parse arguments to check parameter names
	var params map[string]any
	if err := json.Unmarshal([]byte(arguments), &params); err != nil {
		return ValidationResult{
			Allowed: false,
			Reason:  "invalid tool arguments JSON",
		}
	}

	for paramName := range params {
		// Check denied params
		if slices.Contains(policy.DeniedParams, paramName) {
			return ValidationResult{
				Allowed: false,
				Reason:  fmt.Sprintf("parameter %q denied by policy", paramName),
			}
		}

		// If allowed_params is set, check that param is in the list
		if len(policy.AllowedParams) > 0 && !slices.Contains(policy.AllowedParams, paramName) {
			return ValidationResult{
				Allowed: false,
				Reason:  fmt.Sprintf("parameter %q not in allowed params", paramName),
			}
		}
	}

	return ValidationResult{Allowed: true}
}
