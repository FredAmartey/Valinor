package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InviteStore manages tenant invite persistence. The connection pool connects
// as the table owner, so PostgreSQL does NOT enforce RLS on these queries
// (RLS only applies to non-owner roles unless FORCE ROW LEVEL SECURITY is set).
// This is intentional: invite redemption must work for tenantless users who
// haven't joined a tenant yet.
type InviteStore struct {
	pool *pgxpool.Pool
}

func NewInviteStore(pool *pgxpool.Pool) *InviteStore {
	return &InviteStore{pool: pool}
}

func generateCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating invite code: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *InviteStore) Create(ctx context.Context, tenantID, createdBy, role string, ttl time.Duration) (*Invite, error) {
	code, err := generateCode()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(ttl)

	var inv Invite
	err = s.pool.QueryRow(ctx,
		`INSERT INTO tenant_invites (tenant_id, code, role, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, tenant_id, code, role, created_by, expires_at, used_by, used_at, created_at`,
		tenantID, code, role, createdBy, expiresAt,
	).Scan(&inv.ID, &inv.TenantID, &inv.Code, &inv.Role, &inv.CreatedBy,
		&inv.ExpiresAt, &inv.UsedBy, &inv.UsedAt, &inv.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating invite: %w", err)
	}
	return &inv, nil
}

func (s *InviteStore) GetByCode(ctx context.Context, code string) (*Invite, error) {
	var inv Invite
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, code, role, created_by, expires_at, used_by, used_at, created_at
		 FROM tenant_invites WHERE code = $1`,
		code,
	).Scan(&inv.ID, &inv.TenantID, &inv.Code, &inv.Role, &inv.CreatedBy,
		&inv.ExpiresAt, &inv.UsedBy, &inv.UsedAt, &inv.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, ErrInviteNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting invite by code: %w", err)
	}
	return &inv, nil
}

func (s *InviteStore) ListByTenant(ctx context.Context, tenantID string) ([]Invite, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, code, role, created_by, expires_at, used_by, used_at, created_at
		 FROM tenant_invites WHERE tenant_id = $1 ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing invites: %w", err)
	}
	defer rows.Close()

	var invites []Invite
	for rows.Next() {
		var inv Invite
		if err := rows.Scan(&inv.ID, &inv.TenantID, &inv.Code, &inv.Role, &inv.CreatedBy,
			&inv.ExpiresAt, &inv.UsedBy, &inv.UsedAt, &inv.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning invite: %w", err)
		}
		invites = append(invites, inv)
	}
	return invites, nil
}

// Redeem atomically marks an invite as used. Expiry and used-status checks
// are performed in SQL to avoid TOCTOU races between concurrent requests.
// Returns the redeemed invite so callers can read TenantID/Role.
func (s *InviteStore) Redeem(ctx context.Context, code, userID string) (*Invite, error) {
	var inv Invite
	err := s.pool.QueryRow(ctx,
		`UPDATE tenant_invites
		 SET used_by = $1, used_at = now()
		 WHERE code = $2 AND used_at IS NULL AND expires_at > now()
		 RETURNING id, tenant_id, code, role, created_by, expires_at, used_by, used_at, created_at`,
		userID, code,
	).Scan(&inv.ID, &inv.TenantID, &inv.Code, &inv.Role, &inv.CreatedBy,
		&inv.ExpiresAt, &inv.UsedBy, &inv.UsedAt, &inv.CreatedAt)
	if err == pgx.ErrNoRows {
		// Distinguish: not found vs used vs expired
		existing, lookupErr := s.GetByCode(ctx, code)
		if lookupErr != nil {
			return nil, ErrInviteNotFound
		}
		if existing.UsedAt != nil {
			return nil, ErrInviteUsed
		}
		return nil, ErrInviteExpired
	}
	if err != nil {
		return nil, fmt.Errorf("redeeming invite: %w", err)
	}
	return &inv, nil
}

func (s *InviteStore) Delete(ctx context.Context, id, tenantID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM tenant_invites WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return fmt.Errorf("deleting invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	return nil
}
