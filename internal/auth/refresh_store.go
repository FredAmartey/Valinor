package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HashToken computes the SHA-256 hex digest of a raw JWT string.
// Used for reuse detection — we never store the raw token.
func HashToken(rawJWT string) string {
	h := sha256.Sum256([]byte(rawJWT))
	return hex.EncodeToString(h[:])
}

// TokenFamily represents a row in the refresh_token_families table.
type TokenFamily struct {
	ID                string
	TenantID          string
	UserID            string
	CurrentGeneration int
	CurrentTokenHash  string
	RevokedAt         *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// RefreshTokenStore handles refresh token family database operations.
type RefreshTokenStore struct {
	pool *pgxpool.Pool
}

// NewRefreshTokenStore creates a new refresh token store.
func NewRefreshTokenStore(pool *pgxpool.Pool) *RefreshTokenStore {
	return &RefreshTokenStore{pool: pool}
}

// CreateFamily inserts a new token family with a known token hash.
func (s *RefreshTokenStore) CreateFamily(ctx context.Context, tenantID, userID, tokenHash string) (string, error) {
	var familyID string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO refresh_token_families (tenant_id, user_id, current_generation, current_token_hash)
		 VALUES ($1, $2, 1, $3)
		 RETURNING id`,
		tenantID, userID, tokenHash,
	).Scan(&familyID)
	if err != nil {
		return "", fmt.Errorf("creating token family: %w", err)
	}
	return familyID, nil
}

// CreateFamilyAndReturnID creates a family with a placeholder hash.
// Call SetInitialTokenHash immediately after to store the real hash.
// This two-step approach solves the chicken-and-egg problem: the JWT
// needs the family ID, but the hash needs the JWT.
func (s *RefreshTokenStore) CreateFamilyAndReturnID(ctx context.Context, tenantID, userID string) (string, error) {
	var familyID string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO refresh_token_families (tenant_id, user_id, current_generation, current_token_hash)
		 VALUES ($1, $2, 1, 'pending')
		 RETURNING id`,
		tenantID, userID,
	).Scan(&familyID)
	if err != nil {
		return "", fmt.Errorf("creating token family: %w", err)
	}
	return familyID, nil
}

// SetInitialTokenHash stores the real token hash for a newly created family.
func (s *RefreshTokenStore) SetInitialTokenHash(ctx context.Context, familyID, tenantID, tokenHash string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE refresh_token_families
		 SET current_token_hash = $1, updated_at = now()
		 WHERE id = $2 AND tenant_id = $3 AND current_token_hash = 'pending'`,
		tokenHash, familyID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("setting initial token hash: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("family %s not in pending state", familyID)
	}
	return nil
}

// RotateToken atomically validates and rotates a refresh token.
// The single UPDATE checks that the family is active, the hash matches,
// and the generation matches. If any condition fails, zero rows are
// updated and we diagnose the reason.
func (s *RefreshTokenStore) RotateToken(ctx context.Context, familyID, tenantID, presentedHash string, presentedGeneration int, newTokenHash string) (*TokenFamily, error) {
	var family TokenFamily
	err := s.pool.QueryRow(ctx,
		`UPDATE refresh_token_families
		 SET current_generation = current_generation + 1,
		     current_token_hash = $1,
		     updated_at = now()
		 WHERE id = $2
		   AND tenant_id = $3
		   AND current_token_hash = $4
		   AND current_generation = $5
		   AND revoked_at IS NULL
		 RETURNING id, tenant_id, user_id, current_generation, current_token_hash, revoked_at, created_at, updated_at`,
		newTokenHash, familyID, tenantID, presentedHash, presentedGeneration,
	).Scan(
		&family.ID, &family.TenantID, &family.UserID,
		&family.CurrentGeneration, &family.CurrentTokenHash,
		&family.RevokedAt, &family.CreatedAt, &family.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.diagnoseRotationFailure(ctx, familyID, tenantID)
		}
		return nil, fmt.Errorf("rotating token: %w", err)
	}
	return &family, nil
}

// diagnoseRotationFailure determines why a rotation failed and takes
// appropriate action (revoke on reuse detection).
func (s *RefreshTokenStore) diagnoseRotationFailure(ctx context.Context, familyID, tenantID string) error {
	var revokedAt *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT revoked_at FROM refresh_token_families
		 WHERE id = $1 AND tenant_id = $2`,
		familyID, tenantID,
	).Scan(&revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrFamilyNotFound
		}
		return fmt.Errorf("diagnosing rotation failure: %w", err)
	}

	if revokedAt != nil {
		return ErrFamilyRevoked
	}

	// Family exists and is active, but hash/generation didn't match.
	// This means token reuse — revoke the entire family.
	if revokeErr := s.RevokeFamily(ctx, familyID, tenantID); revokeErr != nil {
		return fmt.Errorf("revoking family after reuse detection: %w", revokeErr)
	}
	return ErrTokenReuse
}

// RevokeFamily marks a token family as revoked.
func (s *RefreshTokenStore) RevokeFamily(ctx context.Context, familyID, tenantID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE refresh_token_families
		 SET revoked_at = now(), updated_at = now()
		 WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
		familyID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("revoking token family: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrFamilyNotFound
	}
	return nil
}

// RevokeAllForUser revokes all active token families for a user.
func (s *RefreshTokenStore) RevokeAllForUser(ctx context.Context, userID, tenantID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE refresh_token_families
		 SET revoked_at = now(), updated_at = now()
		 WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
		userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("revoking all families for user: %w", err)
	}
	return nil
}

// GetFamily retrieves a token family by ID and tenant.
func (s *RefreshTokenStore) GetFamily(ctx context.Context, familyID, tenantID string) (*TokenFamily, error) {
	var family TokenFamily
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, user_id, current_generation, current_token_hash, revoked_at, created_at, updated_at
		 FROM refresh_token_families
		 WHERE id = $1 AND tenant_id = $2`,
		familyID, tenantID,
	).Scan(
		&family.ID, &family.TenantID, &family.UserID,
		&family.CurrentGeneration, &family.CurrentTokenHash,
		&family.RevokedAt, &family.CreatedAt, &family.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFamilyNotFound
		}
		return nil, fmt.Errorf("getting token family: %w", err)
	}
	return &family, nil
}
