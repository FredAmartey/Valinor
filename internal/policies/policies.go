package policies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/FredAmartey/heimdall/internal/activity"
	"github.com/FredAmartey/heimdall/internal/platform/database"
)

type Decision string

const (
	DecisionAllow           Decision = "allow"
	DecisionBlock           Decision = "block"
	DecisionRequireApproval Decision = "require_approval"
)

type PolicySet map[string]Decision

var (
	ErrInvalidRiskClass = errors.New("invalid risk class")
	ErrInvalidDecision  = errors.New("invalid policy decision")
)

func DefaultPolicySet() PolicySet {
	return PolicySet{
		activity.RiskClassExternalWrites:         DecisionRequireApproval,
		activity.RiskClassDestructiveActions:     DecisionBlock,
		activity.RiskClassSensitiveDataAccess:    DecisionBlock,
		activity.RiskClassChannelSends:           DecisionAllow,
		activity.RiskClassCredentialedThirdParty: DecisionRequireApproval,
		activity.RiskClassCrossScopeMemoryAccess: DecisionBlock,
	}
}

func ValidatePolicySet(set PolicySet) error {
	for riskClass, decision := range set {
		if _, ok := DefaultPolicySet()[riskClass]; !ok {
			return fmt.Errorf("%w: %s", ErrInvalidRiskClass, riskClass)
		}
		switch decision {
		case DecisionAllow, DecisionBlock, DecisionRequireApproval:
		default:
			return fmt.Errorf("%w: %s", ErrInvalidDecision, decision)
		}
	}
	return nil
}

func Evaluate(defaults, overrides PolicySet, riskClass string) Decision {
	if override, ok := overrides[riskClass]; ok {
		return override
	}
	if decision, ok := defaults[riskClass]; ok {
		return decision
	}
	if fallback, ok := DefaultPolicySet()[riskClass]; ok {
		return fallback
	}
	return DecisionBlock
}

type Store struct{}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) GetTenantDefaults(ctx context.Context, q database.Querier, tenantID uuid.UUID) (PolicySet, error) {
	var raw json.RawMessage
	if err := q.QueryRow(ctx, `SELECT settings FROM tenants WHERE id = $1`, tenantID).Scan(&raw); err != nil {
		return nil, fmt.Errorf("loading tenant settings: %w", err)
	}
	return extractPolicies(raw, "risk_class_policies"), nil
}

func (s *Store) PutTenantDefaults(ctx context.Context, q database.Querier, tenantID uuid.UUID, set PolicySet) error {
	if err := ValidatePolicySet(set); err != nil {
		return err
	}
	payload, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("marshaling policy defaults: %w", err)
	}
	if _, err := q.Exec(ctx,
		`UPDATE tenants
		    SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{risk_class_policies}', $2::jsonb, true),
		        updated_at = now()
		  WHERE id = $1`,
		tenantID,
		payload,
	); err != nil {
		return fmt.Errorf("updating tenant policy defaults: %w", err)
	}
	return nil
}

func (s *Store) GetAgentOverrides(ctx context.Context, q database.Querier, tenantID, agentID uuid.UUID) (PolicySet, error) {
	var raw json.RawMessage
	if err := q.QueryRow(ctx, `SELECT config FROM agent_instances WHERE id = $1 AND tenant_id = $2`, agentID, tenantID).Scan(&raw); err != nil {
		return nil, fmt.Errorf("loading agent config: %w", err)
	}
	return extractPolicies(raw, "policy_overrides"), nil
}

func (s *Store) PutAgentOverrides(ctx context.Context, q database.Querier, tenantID, agentID uuid.UUID, set PolicySet) error {
	if err := ValidatePolicySet(set); err != nil {
		return err
	}
	payload, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("marshaling agent overrides: %w", err)
	}
	if _, err := q.Exec(ctx,
		`UPDATE agent_instances
		    SET config = jsonb_set(COALESCE(config, '{}'::jsonb), '{policy_overrides}', $2::jsonb, true)
		  WHERE id = $1 AND tenant_id = $3`,
		agentID,
		payload,
		tenantID,
	); err != nil {
		return fmt.Errorf("updating agent policy overrides: %w", err)
	}
	return nil
}

func extractPolicies(raw json.RawMessage, key string) PolicySet {
	if len(raw) == 0 {
		return PolicySet{}
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return PolicySet{}
	}
	value, ok := doc[key]
	if !ok || len(value) == 0 {
		return PolicySet{}
	}
	var set PolicySet
	if err := json.Unmarshal(value, &set); err != nil {
		return PolicySet{}
	}
	return set
}
