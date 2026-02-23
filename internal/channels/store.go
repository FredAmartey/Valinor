package channels

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// Store handles channels database operations.
// Methods accept database.Querier so they can run inside WithTenantConnection.
type Store struct{}

// NewStore creates a new channels store.
func NewStore() *Store {
	return &Store{}
}

// GetLinkByIdentity returns the tenant-scoped channel link for platform identity.
func (s *Store) GetLinkByIdentity(ctx context.Context, q database.Querier, platform, platformUserID string) (*ChannelLink, error) {
	if platform == "" {
		return nil, ErrPlatformEmpty
	}
	if platformUserID == "" {
		return nil, ErrIdentityEmpty
	}

	var link ChannelLink
	var state string
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, user_id, platform, platform_user_id, state, verified, created_at, verified_at, revoked_at, COALESCE(verification_method, ''), verification_metadata
		 FROM channel_links
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND platform = $1
		   AND platform_user_id = $2`,
		platform, platformUserID,
	).Scan(
		&link.ID,
		&link.TenantID,
		&link.UserID,
		&link.Platform,
		&link.PlatformUserID,
		&state,
		&link.Verified,
		&link.CreatedAt,
		&link.VerifiedAt,
		&link.RevokedAt,
		&link.VerificationMethod,
		&link.VerificationMetadata,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrLinkNotFound
		}
		return nil, fmt.Errorf("getting channel link by identity: %w", err)
	}
	link.State = LinkState(state)
	return &link, nil
}

// InsertIdempotency records a message idempotency key.
// It returns true when this is the first-seen key and false on duplicate.
func (s *Store) InsertIdempotency(
	ctx context.Context,
	q database.Querier,
	platform string,
	platformUserID string,
	platformMessageID string,
	idempotencyKey string,
	payloadFingerprint string,
	correlationID string,
	expiresAt time.Time,
) (bool, error) {
	if platform == "" {
		return false, ErrPlatformEmpty
	}
	if platformUserID == "" {
		return false, ErrIdentityEmpty
	}
	if idempotencyKey == "" {
		return false, ErrIdempotencyKey
	}
	if payloadFingerprint == "" {
		return false, ErrFingerprint
	}
	if correlationID == "" {
		return false, ErrCorrelationID
	}
	if expiresAt.IsZero() {
		return false, ErrExpiryRequired
	}

	var insertedID uuid.UUID
	err := q.QueryRow(ctx,
		`INSERT INTO channel_messages (
			tenant_id,
			platform,
			platform_user_id,
			platform_message_id,
			idempotency_key,
			payload_fingerprint,
			correlation_id,
			status,
			expires_at
		)
		VALUES (
			current_setting('app.current_tenant_id', true)::UUID,
			$1, $2, $3, $4, $5, $6, $7, $8
		)
		ON CONFLICT (tenant_id, platform, idempotency_key) DO NOTHING
		RETURNING id`,
		platform,
		platformUserID,
		platformMessageID,
		idempotencyKey,
		payloadFingerprint,
		correlationID,
		MessageStatusAccepted,
		expiresAt,
	).Scan(&insertedID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("inserting channel idempotency key: %w", err)
	}
	return true, nil
}
