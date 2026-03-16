package connectors

import (
	"errors"

	"github.com/FredAmartey/heimdall/internal/policies"
)

type GovernanceResult struct {
	Governed  bool
	Decision  policies.Decision
	RiskClass string
	Tool      ConnectorTool
}

func ResolveToolDefinition(rawTools []byte, toolName string) (ConnectorTool, error) {
	tools, err := ParseTools(rawTools)
	if err != nil {
		return ConnectorTool{}, err
	}
	for _, tool := range tools {
		if tool.Name == toolName {
			return tool, nil
		}
	}
	return ConnectorTool{}, ErrNotFound
}

func EvaluateGovernance(tool ConnectorTool, defaults, overrides policies.PolicySet) (GovernanceResult, error) {
	result := GovernanceResult{
		Decision: policies.DecisionAllow,
		Tool:     tool,
	}

	switch tool.ActionType {
	case "", "read":
		return result, nil
	case "write":
		result.Governed = true
		result.RiskClass = tool.RiskClass
		if tool.RiskClass == "" {
			result.Decision = policies.DecisionBlock
			return result, ErrConnectorToolRiskClassNeeded
		}
		result.Decision = policies.Evaluate(defaults, overrides, tool.RiskClass)
		return result, nil
	default:
		result.Governed = true
		result.Decision = policies.DecisionBlock
		return result, ErrConnectorToolActionType
	}
}

func IsGovernedWrite(tool ConnectorTool) bool {
	return tool.ActionType == "write"
}

func IsToolMissingGovernanceMetadata(err error) bool {
	return errors.Is(err, ErrConnectorToolRiskClassNeeded) || errors.Is(err, ErrConnectorToolActionType)
}
