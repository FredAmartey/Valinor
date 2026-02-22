package main

// ToolPolicy defines parameter-level constraints for a tool.
type ToolPolicy struct {
	AllowedParams []string `json:"allowed_params"`
	DeniedParams  []string `json:"denied_params"`
	MaxResults    int      `json:"max_results,omitempty"`
}
