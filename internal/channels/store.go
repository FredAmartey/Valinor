package channels

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// ListLinks returns all channel links visible in tenant scope.
func (s *Store) ListLinks(ctx context.Context, q database.Querier) ([]ChannelLink, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, user_id, platform, platform_user_id, state, verified, created_at, verified_at, revoked_at, COALESCE(verification_method, ''), verification_metadata
		 FROM channel_links
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		 ORDER BY created_at DESC, id DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing channel links: %w", err)
	}
	defer rows.Close()

	links := make([]ChannelLink, 0)
	for rows.Next() {
		var link ChannelLink
		var state string
		if scanErr := rows.Scan(
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
		); scanErr != nil {
			return nil, fmt.Errorf("scanning channel link row: %w", scanErr)
		}
		link.State = LinkState(state)
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating channel link rows: %w", err)
	}

	return links, nil
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

// UpsertLink creates or updates a tenant-scoped link for a platform identity.
func (s *Store) UpsertLink(ctx context.Context, q database.Querier, params UpsertLinkParams) (*ChannelLink, error) {
	if strings.TrimSpace(params.UserID) == "" {
		return nil, ErrUserIDRequired
	}
	userID, err := uuid.Parse(strings.TrimSpace(params.UserID))
	if err != nil {
		return nil, fmt.Errorf("parsing user id: %w", err)
	}

	platform := strings.ToLower(strings.TrimSpace(params.Platform))
	if platform == "" {
		return nil, ErrPlatformEmpty
	}
	platformUserID := strings.TrimSpace(params.PlatformUserID)
	if platformUserID == "" {
		return nil, ErrIdentityEmpty
	}

	state := params.State
	if state == "" {
		state = LinkStatePendingVerification
	}
	if state != LinkStatePendingVerification && state != LinkStateVerified && state != LinkStateRevoked {
		return nil, ErrLinkState
	}

	verificationMetadata := params.VerificationMetadata
	if len(verificationMetadata) == 0 {
		verificationMetadata = json.RawMessage(`{}`)
	}
	if !json.Valid(verificationMetadata) {
		return nil, fmt.Errorf("verification metadata must be valid JSON")
	}

	var exists bool
	err = q.QueryRow(ctx,
		`SELECT true
		 FROM users
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND id = $1`,
		userID,
	).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("resolving channel link user: %w", err)
	}

	now := time.Now().UTC()
	verified := false
	var verifiedAt *time.Time
	var revokedAt *time.Time
	switch state {
	case LinkStateVerified:
		verified = true
		verifiedAt = &now
	case LinkStateRevoked:
		revokedAt = &now
	}

	var link ChannelLink
	var stateValue string
	err = q.QueryRow(ctx,
		`INSERT INTO channel_links (
			tenant_id, user_id, platform, platform_user_id, state, verified, verified_at, revoked_at, verification_method, verification_metadata
		)
		VALUES (
			current_setting('app.current_tenant_id', true)::UUID,
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (tenant_id, platform, platform_user_id)
		DO UPDATE
		SET user_id = EXCLUDED.user_id,
		    state = EXCLUDED.state,
		    verified = EXCLUDED.verified,
		    verified_at = EXCLUDED.verified_at,
		    revoked_at = EXCLUDED.revoked_at,
		    verification_method = EXCLUDED.verification_method,
		    verification_metadata = EXCLUDED.verification_metadata
		RETURNING id, tenant_id, user_id, platform, platform_user_id, state, verified, created_at, verified_at, revoked_at, COALESCE(verification_method, ''), verification_metadata`,
		userID,
		platform,
		platformUserID,
		state,
		verified,
		verifiedAt,
		revokedAt,
		strings.TrimSpace(params.VerificationMethod),
		verificationMetadata,
	).Scan(
		&link.ID,
		&link.TenantID,
		&link.UserID,
		&link.Platform,
		&link.PlatformUserID,
		&stateValue,
		&link.Verified,
		&link.CreatedAt,
		&link.VerifiedAt,
		&link.RevokedAt,
		&link.VerificationMethod,
		&link.VerificationMetadata,
	)
	if err != nil {
		return nil, fmt.Errorf("upserting channel link: %w", err)
	}
	link.State = LinkState(stateValue)

	return &link, nil
}

// DeleteLink deletes a tenant-scoped channel link by id.
func (s *Store) DeleteLink(ctx context.Context, q database.Querier, id string) error {
	linkID := strings.TrimSpace(id)
	if linkID == "" {
		return ErrLinkIDRequired
	}
	parsedID, err := uuid.Parse(linkID)
	if err != nil {
		return ErrLinkIDInvalid
	}

	cmd, err := q.Exec(ctx,
		`DELETE FROM channel_links
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND id = $1`,
		parsedID,
	)
	if err != nil {
		return fmt.Errorf("deleting channel link: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrLinkNotFound
	}
	return nil
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

// UpdateMessageStatus updates an existing idempotency row with final decision status and metadata.
func (s *Store) UpdateMessageStatus(
	ctx context.Context,
	q database.Querier,
	platform string,
	idempotencyKey string,
	status string,
	metadata json.RawMessage,
) error {
	if platform == "" {
		return ErrPlatformEmpty
	}
	if idempotencyKey == "" {
		return ErrIdempotencyKey
	}
	statusValue := strings.TrimSpace(status)
	if statusValue == "" {
		return ErrStatusRequired
	}

	meta := metadata
	if len(meta) == 0 {
		meta = json.RawMessage(`{}`)
	}
	if !json.Valid(meta) {
		return fmt.Errorf("status metadata must be valid JSON")
	}

	cmd, err := q.Exec(ctx,
		`UPDATE channel_messages
		 SET status = $3,
		     metadata = COALESCE(metadata, '{}'::jsonb) || $4::jsonb
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND platform = $1
		   AND idempotency_key = $2`,
		platform,
		idempotencyKey,
		statusValue,
		meta,
	)
	if err != nil {
		return fmt.Errorf("updating channel message status: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrMessageNotFound
	}
	return nil
}
