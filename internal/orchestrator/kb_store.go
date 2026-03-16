package orchestrator

import (
	"context"
	"fmt"

	"github.com/FredAmartey/heimdall/internal/platform/database"
)

// KBStore queries knowledge_bases and knowledge_base_grants.
type KBStore struct{}

// NewKBStore creates a KBStore.
func NewKBStore() *KBStore {
	return &KBStore{}
}

// GrantsForUser returns all knowledge bases granted to a user, either directly,
// via their department, or via their roles. Uses the owner pool (no RLS).
// SECURITY: tenantID must be sourced from an authenticated session, never from user input.
func (s *KBStore) GrantsForUser(ctx context.Context, q database.Querier, tenantID, userID, departmentID string) ([]KBMount, error) {
	rows, err := q.Query(ctx,
		`SELECT DISTINCT kb.id, kb.name
		 FROM knowledge_bases kb
		 JOIN knowledge_base_grants g ON g.knowledge_base_id = kb.id
		 WHERE kb.tenant_id = $1
		   AND (
		       (g.grant_type = 'user' AND g.grant_target_id = $2::UUID)
		    OR (g.grant_type = 'department' AND g.grant_target_id = $3::UUID)
		    OR (g.grant_type = 'role' AND g.grant_target_id IN (
		            SELECT role_id FROM user_roles WHERE user_id = $2::UUID
		        ))
		   )
		 ORDER BY kb.name`,
		tenantID, userID, departmentID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying knowledge base grants: %w", err)
	}
	defer rows.Close()

	var grants []KBMount
	for rows.Next() {
		var g KBMount
		if err := rows.Scan(&g.ID, &g.Name); err != nil {
			return nil, fmt.Errorf("scanning knowledge base grant: %w", err)
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}
