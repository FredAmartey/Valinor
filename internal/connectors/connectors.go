package connectors

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Connector represents a registered MCP server for a tenant.
type Connector struct {
	ID            uuid.UUID       `json:"id"`
	TenantID      uuid.UUID       `json:"tenant_id"`
	Name          string          `json:"name"`
	ConnectorType string          `json:"connector_type"`
	Endpoint      string          `json:"endpoint"`
	AuthConfig    json.RawMessage `json:"auth_config"`
	Resources     json.RawMessage `json:"resources"`
	Tools         json.RawMessage `json:"tools"`
	Status        string          `json:"status"`
	CreatedAt     time.Time       `json:"created_at"`
}

type ConnectorTool struct {
	Name                    string `json:"name"`
	ActionType              string `json:"action_type,omitempty"`
	RiskClass               string `json:"risk_class,omitempty"`
	TargetType              string `json:"target_type,omitempty"`
	TargetLabelTemplate     string `json:"target_label_template,omitempty"`
	ApprovalSummaryTemplate string `json:"approval_summary_template,omitempty"`
}

// AgentConnectorConfig is the reduced connector shape injected into agent config.
type AgentConnectorConfig struct {
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Endpoint string          `json:"endpoint"`
	Auth     json.RawMessage `json:"auth"`
	Tools    json.RawMessage `json:"tools"`
}

var (
	ErrNotFound                     = errors.New("connector not found")
	ErrNameEmpty                    = errors.New("connector name is required")
	ErrNameTaken                    = errors.New("connector name already exists")
	ErrEndpointEmpty                = errors.New("connector endpoint is required")
	ErrConnectorToolNameEmpty       = errors.New("connector tool name is required")
	ErrConnectorToolActionType      = errors.New("connector tool action_type must be read or write")
	ErrConnectorToolRiskClassNeeded = errors.New("connector write tools must declare a risk_class")
)
