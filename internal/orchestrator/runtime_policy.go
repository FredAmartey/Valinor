package orchestrator

import (
	"encoding/json"
	"fmt"
	"strings"
)

// enforceOpenClawRuntimePolicy injects secure defaults and rejects explicitly insecure overrides.
func enforceOpenClawRuntimePolicy(config map[string]any) (map[string]any, error) {
	normalized, err := cloneConfigMap(config)
	if err != nil {
		return nil, fmt.Errorf("normalizing config: %w", err)
	}

	sandboxMode, found, err := nestedGetString(normalized, "agents", "defaults", "sandbox", "mode")
	if err != nil {
		return nil, fmt.Errorf("invalid agents.defaults.sandbox.mode: %w", err)
	}
	if found {
		mode := strings.ToLower(strings.TrimSpace(sandboxMode))
		switch mode {
		case "non-main", "all":
			// allowed
		case "", "off", "main":
			return nil, fmt.Errorf("agents.defaults.sandbox.mode must not be %q", sandboxMode)
		default:
			return nil, fmt.Errorf("agents.defaults.sandbox.mode %q is not allowed", sandboxMode)
		}
	} else {
		nestedSet(normalized, "non-main", "agents", "defaults", "sandbox", "mode")
	}

	execWorkspaceOnly, found, err := nestedGetBool(normalized, "tools", "exec", "workspaceOnly")
	if err != nil {
		return nil, fmt.Errorf("invalid tools.exec.workspaceOnly: %w", err)
	}
	if found {
		if !execWorkspaceOnly {
			return nil, fmt.Errorf("tools.exec.workspaceOnly must not be false")
		}
	} else {
		nestedSet(normalized, true, "tools", "exec", "workspaceOnly")
	}

	applyPatchWorkspaceOnly, found, err := nestedGetBool(normalized, "tools", "exec", "applyPatch", "workspaceOnly")
	if err != nil {
		return nil, fmt.Errorf("invalid tools.exec.applyPatch.workspaceOnly: %w", err)
	}
	if found {
		if !applyPatchWorkspaceOnly {
			return nil, fmt.Errorf("tools.exec.applyPatch.workspaceOnly must not be false")
		}
	} else {
		nestedSet(normalized, true, "tools", "exec", "applyPatch", "workspaceOnly")
	}

	bind, found, err := nestedGetString(normalized, "gateway", "bind")
	if err != nil {
		return nil, fmt.Errorf("invalid gateway.bind: %w", err)
	}
	if found {
		switch strings.ToLower(strings.TrimSpace(bind)) {
		case "loopback", "localhost", "127.0.0.1", "::1":
			// allowed
		default:
			return nil, fmt.Errorf("gateway.bind must be loopback/local-only")
		}
	} else {
		nestedSet(normalized, "loopback", "gateway", "bind")
	}

	return normalized, nil
}

func cloneConfigMap(config map[string]any) (map[string]any, error) {
	if config == nil {
		return map[string]any{}, nil
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, err
	}
	if cloned == nil {
		cloned = map[string]any{}
	}
	return cloned, nil
}

func nestedGetBool(root map[string]any, path ...string) (bool, bool, error) {
	val, found, err := nestedGet(root, path...)
	if err != nil || !found {
		return false, found, err
	}
	b, ok := val.(bool)
	if !ok {
		return false, true, fmt.Errorf("must be a boolean")
	}
	return b, true, nil
}

func nestedGetString(root map[string]any, path ...string) (string, bool, error) {
	val, found, err := nestedGet(root, path...)
	if err != nil || !found {
		return "", found, err
	}
	s, ok := val.(string)
	if !ok {
		return "", true, fmt.Errorf("must be a string")
	}
	return s, true, nil
}

func nestedGet(root map[string]any, path ...string) (any, bool, error) {
	if len(path) == 0 {
		return nil, false, fmt.Errorf("path is required")
	}
	var cur any = root
	for i, part := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("path segment %q must be an object", path[i-1])
		}
		next, ok := m[part]
		if !ok {
			return nil, false, nil
		}
		cur = next
	}
	return cur, true, nil
}

func nestedSet(root map[string]any, value any, path ...string) {
	if len(path) == 0 {
		return
	}
	cur := root
	for i := 0; i < len(path)-1; i++ {
		part := path[i]
		next, ok := cur[part]
		if !ok {
			created := map[string]any{}
			cur[part] = created
			cur = created
			continue
		}
		nextMap, ok := next.(map[string]any)
		if !ok {
			nextMap = map[string]any{}
			cur[part] = nextMap
		}
		cur = nextMap
	}
	cur[path[len(path)-1]] = value
}
