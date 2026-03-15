package connectors

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func ValidateToolsJSON(raw json.RawMessage) error {
	tools, err := ParseTools(raw)
	if err != nil {
		return err
	}
	for _, tool := range tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			return ErrConnectorToolNameEmpty
		}
		actionType := strings.TrimSpace(tool.ActionType)
		switch actionType {
		case "", "read":
		case "write":
			if strings.TrimSpace(tool.RiskClass) == "" {
				return ErrConnectorToolRiskClassNeeded
			}
		default:
			return ErrConnectorToolActionType
		}
	}
	return nil
}

func ParseTools(raw json.RawMessage) ([]ConnectorTool, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}

	var names []string
	if err := json.Unmarshal(raw, &names); err == nil {
		tools := make([]ConnectorTool, 0, len(names))
		for _, name := range names {
			tools = append(tools, ConnectorTool{Name: name})
		}
		return tools, nil
	}

	var tools []ConnectorTool
	if err := json.Unmarshal(raw, &tools); err != nil {
		return nil, fmt.Errorf("parsing connector tools: %w", err)
	}
	return tools, nil
}

func EncodeTools(tools []ConnectorTool) json.RawMessage {
	if len(tools) == 0 {
		return json.RawMessage(`[]`)
	}
	encoded, err := json.Marshal(tools)
	if err != nil {
		panic(errors.New("connector tool encoding should never fail"))
	}
	return encoded
}
