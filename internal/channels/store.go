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
type Store struct {
	credentialCrypto *CredentialCrypto
}

// StoreOption customizes store dependencies.
type StoreOption func(*Store)

// WithCredentialCrypto configures credential encryption/decryption for provider secret fields.
func WithCredentialCrypto(crypto *CredentialCrypto) StoreOption {
	return func(store *Store) {
		if store == nil {
			return
		}
		store.credentialCrypto = crypto
	}
}

// NewStore creates a new channels store.
func NewStore(options ...StoreOption) *Store {
	store := &Store{}
	for _, option := range options {
		if option != nil {
			option(store)
		}
	}
	return store
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

// GetProviderCredential returns tenant-scoped provider credentials.
func (s *Store) GetProviderCredential(ctx context.Context, q database.Querier, provider string) (*ProviderCredential, error) {
	normalizedProvider, err := normalizeCredentialProvider(provider)
	if err != nil {
		return nil, err
	}

	var credential ProviderCredential
	err = q.QueryRow(ctx,
		`SELECT id, tenant_id, provider, access_token, signing_secret, secret_token, api_base_url, api_version, phone_number_id, created_at, updated_at
		 FROM channel_provider_credentials
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND provider = $1`,
		normalizedProvider,
	).Scan(
		&credential.ID,
		&credential.TenantID,
		&credential.Provider,
		&credential.AccessToken,
		&credential.SigningSecret,
		&credential.SecretToken,
		&credential.APIBaseURL,
		&credential.APIVersion,
		&credential.PhoneNumberID,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderCredentialNotFound
		}
		return nil, fmt.Errorf("getting provider credential: %w", err)
	}
	if err := s.decryptCredentialFields(&credential); err != nil {
		return nil, fmt.Errorf("getting provider credential: %w", err)
	}
	return &credential, nil
}

// UpsertProviderCredential creates or updates tenant-scoped provider credentials.
func (s *Store) UpsertProviderCredential(ctx context.Context, q database.Querier, params UpsertProviderCredentialParams) (*ProviderCredential, error) {
	provider, err := normalizeCredentialProvider(params.Provider)
	if err != nil {
		return nil, err
	}

	accessToken := strings.TrimSpace(params.AccessToken)
	if accessToken == "" {
		return nil, ErrProviderAccessTokenRequired
	}

	signingSecret := strings.TrimSpace(params.SigningSecret)
	secretToken := strings.TrimSpace(params.SecretToken)
	phoneNumberID := strings.TrimSpace(params.PhoneNumberID)
	if provider == "whatsapp" && phoneNumberID == "" {
		return nil, ErrProviderPhoneNumberIDRequired
	}
	if provider == "slack" || provider == "whatsapp" {
		if signingSecret == "" {
			return nil, ErrProviderSigningSecretRequired
		}
	}
	if provider == "telegram" && secretToken == "" {
		return nil, ErrProviderSecretTokenRequired
	}

	encryptedAccessToken, err := s.encryptCredentialValue(accessToken)
	if err != nil {
		return nil, fmt.Errorf("upserting provider credential: %w", err)
	}
	encryptedSigningSecret, err := s.encryptCredentialValue(signingSecret)
	if err != nil {
		return nil, fmt.Errorf("upserting provider credential: %w", err)
	}
	encryptedSecretToken, err := s.encryptCredentialValue(secretToken)
	if err != nil {
		return nil, fmt.Errorf("upserting provider credential: %w", err)
	}

	var credential ProviderCredential
	err = q.QueryRow(ctx,
		`INSERT INTO channel_provider_credentials (
			tenant_id, provider, access_token, signing_secret, secret_token, api_base_url, api_version, phone_number_id
		) VALUES (
			current_setting('app.current_tenant_id', true)::UUID, $1, $2, $3, $4, $5, $6, $7
		)
		ON CONFLICT (tenant_id, provider)
		DO UPDATE SET
			access_token = EXCLUDED.access_token,
			signing_secret = EXCLUDED.signing_secret,
			secret_token = EXCLUDED.secret_token,
			api_base_url = EXCLUDED.api_base_url,
			api_version = EXCLUDED.api_version,
			phone_number_id = EXCLUDED.phone_number_id,
			updated_at = now()
		RETURNING id, tenant_id, provider, access_token, signing_secret, secret_token, api_base_url, api_version, phone_number_id, created_at, updated_at`,
		provider,
		encryptedAccessToken,
		encryptedSigningSecret,
		encryptedSecretToken,
		strings.TrimSpace(params.APIBaseURL),
		strings.TrimSpace(params.APIVersion),
		phoneNumberID,
	).Scan(
		&credential.ID,
		&credential.TenantID,
		&credential.Provider,
		&credential.AccessToken,
		&credential.SigningSecret,
		&credential.SecretToken,
		&credential.APIBaseURL,
		&credential.APIVersion,
		&credential.PhoneNumberID,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upserting provider credential: %w", err)
	}
	if err := s.decryptCredentialFields(&credential); err != nil {
		return nil, fmt.Errorf("upserting provider credential: %w", err)
	}
	return &credential, nil
}

// DeleteProviderCredential removes tenant-scoped provider credentials.
func (s *Store) DeleteProviderCredential(ctx context.Context, q database.Querier, provider string) error {
	normalizedProvider, err := normalizeCredentialProvider(provider)
	if err != nil {
		return err
	}

	cmd, err := q.Exec(ctx,
		`DELETE FROM channel_provider_credentials
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND provider = $1`,
		normalizedProvider,
	)
	if err != nil {
		return fmt.Errorf("deleting provider credential: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrProviderCredentialNotFound
	}
	return nil
}

func normalizeCredentialProvider(provider string) (string, error) {
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	if normalizedProvider == "" {
		return "", ErrPlatformEmpty
	}

	switch normalizedProvider {
	case "slack", "whatsapp", "telegram":
		return normalizedProvider, nil
	default:
		return "", ErrProviderUnsupported
	}
}

func (s *Store) encryptCredentialValue(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	if s.credentialCrypto == nil {
		return "", ErrProviderCredentialCipherRequired
	}

	encrypted, err := s.credentialCrypto.Encrypt(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrProviderCredentialEncryptFailed, err)
	}
	return encrypted, nil
}

func (s *Store) decryptCredentialValue(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	if !IsEncryptedCredentialValue(trimmed) {
		return trimmed, nil
	}
	if s.credentialCrypto == nil {
		return "", ErrProviderCredentialCipherRequired
	}

	decrypted, err := s.credentialCrypto.Decrypt(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrProviderCredentialDecryptFailed, err)
	}
	return decrypted, nil
}

func (s *Store) decryptCredentialFields(credential *ProviderCredential) error {
	if credential == nil {
		return nil
	}

	accessToken, err := s.decryptCredentialValue(credential.AccessToken)
	if err != nil {
		return fmt.Errorf("decrypting access token: %w", err)
	}
	signingSecret, err := s.decryptCredentialValue(credential.SigningSecret)
	if err != nil {
		return fmt.Errorf("decrypting signing secret: %w", err)
	}
	secretToken, err := s.decryptCredentialValue(credential.SecretToken)
	if err != nil {
		return fmt.Errorf("decrypting secret token: %w", err)
	}

	credential.AccessToken = accessToken
	credential.SigningSecret = signingSecret
	credential.SecretToken = secretToken
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

// DeleteExpiredMessages removes tenant-scoped idempotency rows whose expiry is in the past.
// Returns the number of deleted rows in this call.
func (s *Store) DeleteExpiredMessages(
	ctx context.Context,
	q database.Querier,
	before time.Time,
	limit int,
) (int, error) {
	if before.IsZero() {
		return 0, ErrExpiryRequired
	}
	if limit <= 0 {
		return 0, fmt.Errorf("cleanup limit must be greater than zero")
	}

	cmd, err := q.Exec(ctx,
		`WITH expired AS (
			SELECT id
			FROM channel_messages
			WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
			  AND expires_at <= $1
			ORDER BY expires_at ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM channel_messages msg
		USING expired
		WHERE msg.id = expired.id`,
		before,
		limit,
	)
	if err != nil {
		return 0, fmt.Errorf("deleting expired channel messages: %w", err)
	}

	return int(cmd.RowsAffected()), nil
}

// GetMessageIDByIdempotencyKey resolves a tenant-scoped channel message ID.
func (s *Store) GetMessageIDByIdempotencyKey(ctx context.Context, q database.Querier, platform, idempotencyKey string) (uuid.UUID, error) {
	if platform == "" {
		return uuid.Nil, ErrPlatformEmpty
	}
	if idempotencyKey == "" {
		return uuid.Nil, ErrIdempotencyKey
	}

	var messageID uuid.UUID
	err := q.QueryRow(ctx,
		`SELECT id
		 FROM channel_messages
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND platform = $1
		   AND idempotency_key = $2`,
		platform,
		idempotencyKey,
	).Scan(&messageID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrMessageNotFound
		}
		return uuid.Nil, fmt.Errorf("resolving message id by idempotency key: %w", err)
	}

	return messageID, nil
}

// GetMessageByIdempotencyKey resolves a tenant-scoped channel message row.
func (s *Store) GetMessageByIdempotencyKey(ctx context.Context, q database.Querier, platform, idempotencyKey string) (*ChannelMessageRecord, error) {
	if platform == "" {
		return nil, ErrPlatformEmpty
	}
	if idempotencyKey == "" {
		return nil, ErrIdempotencyKey
	}

	var record ChannelMessageRecord
	err := q.QueryRow(ctx,
		`SELECT id, platform, platform_user_id, COALESCE(platform_message_id, ''), idempotency_key,
		        correlation_id, status, metadata
		 FROM channel_messages
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND platform = $1
		   AND idempotency_key = $2`,
		platform,
		idempotencyKey,
	).Scan(
		&record.ID,
		&record.Platform,
		&record.PlatformUserID,
		&record.PlatformMessageID,
		&record.IdempotencyKey,
		&record.CorrelationID,
		&record.Status,
		&record.Metadata,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrMessageNotFound
		}
		return nil, fmt.Errorf("resolving message by idempotency key: %w", err)
	}

	return &record, nil
}

// EnqueueOutbound inserts a new tenant-scoped outbox job for async provider send.
func (s *Store) EnqueueOutbound(ctx context.Context, q database.Querier, params EnqueueOutboundParams) (*ChannelOutbox, error) {
	messageIDValue := strings.TrimSpace(params.ChannelMessageID)
	if messageIDValue == "" {
		return nil, ErrMessageNotFound
	}
	messageID, err := uuid.Parse(messageIDValue)
	if err != nil {
		return nil, fmt.Errorf("parsing channel message id: %w", err)
	}

	provider := strings.ToLower(strings.TrimSpace(params.Provider))
	if provider == "" {
		return nil, ErrPlatformEmpty
	}
	recipientID := strings.TrimSpace(params.RecipientID)
	if recipientID == "" {
		return nil, ErrIdentityEmpty
	}

	payload := params.Payload
	if len(payload) == 0 {
		return nil, ErrPayloadRequired
	}
	if !json.Valid(payload) {
		return nil, fmt.Errorf("payload must be valid JSON")
	}

	maxAttempts := params.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	var outbox ChannelOutbox
	var status string
	err = q.QueryRow(ctx,
		`INSERT INTO channel_outbox (
			tenant_id,
			channel_message_id,
			provider,
			recipient_id,
			payload,
			status,
			max_attempts
		)
		SELECT
			current_setting('app.current_tenant_id', true)::UUID,
			msg.id,
			$2, $3, $4::jsonb, $5, $6
		FROM channel_messages msg
		WHERE msg.id = $1
		  AND msg.tenant_id = current_setting('app.current_tenant_id', true)::UUID
		RETURNING id, tenant_id, channel_message_id, provider, recipient_id, payload, status,
		          attempt_count, max_attempts, next_attempt_at, last_error, locked_at, sent_at, created_at, updated_at`,
		messageID,
		provider,
		recipientID,
		payload,
		OutboxStatusPending,
		maxAttempts,
	).Scan(
		&outbox.ID,
		&outbox.TenantID,
		&outbox.ChannelMessageID,
		&outbox.Provider,
		&outbox.RecipientID,
		&outbox.Payload,
		&status,
		&outbox.AttemptCount,
		&outbox.MaxAttempts,
		&outbox.NextAttemptAt,
		&outbox.LastError,
		&outbox.LockedAt,
		&outbox.SentAt,
		&outbox.CreatedAt,
		&outbox.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrMessageNotFound
		}
		return nil, fmt.Errorf("enqueuing outbound job: %w", err)
	}
	outbox.Status = OutboxStatus(status)
	return &outbox, nil
}

// ClaimPendingOutbox atomically marks due pending jobs as sending and returns them.
func (s *Store) ClaimPendingOutbox(ctx context.Context, q database.Querier, now time.Time, limit int) ([]ChannelOutbox, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 {
		limit = 1
	}

	rows, err := q.Query(ctx,
		`WITH due AS (
			SELECT id
			FROM channel_outbox
			WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
			  AND status = $1
			  AND next_attempt_at <= $2
			ORDER BY next_attempt_at ASC, created_at ASC
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE channel_outbox outbox
		SET status = $4,
		    locked_at = now(),
		    updated_at = now()
		FROM due
		WHERE outbox.id = due.id
		RETURNING outbox.id, outbox.tenant_id, outbox.channel_message_id, outbox.provider, outbox.recipient_id,
		          outbox.payload, outbox.status, outbox.attempt_count, outbox.max_attempts, outbox.next_attempt_at,
		          outbox.last_error, outbox.locked_at, outbox.sent_at, outbox.created_at, outbox.updated_at`,
		OutboxStatusPending,
		now,
		limit,
		OutboxStatusSending,
	)
	if err != nil {
		return nil, fmt.Errorf("claiming pending outbox jobs: %w", err)
	}
	defer rows.Close()

	claimed := make([]ChannelOutbox, 0)
	for rows.Next() {
		var job ChannelOutbox
		var status string
		if scanErr := rows.Scan(
			&job.ID,
			&job.TenantID,
			&job.ChannelMessageID,
			&job.Provider,
			&job.RecipientID,
			&job.Payload,
			&status,
			&job.AttemptCount,
			&job.MaxAttempts,
			&job.NextAttemptAt,
			&job.LastError,
			&job.LockedAt,
			&job.SentAt,
			&job.CreatedAt,
			&job.UpdatedAt,
		); scanErr != nil {
			return nil, fmt.Errorf("scanning claimed outbox row: %w", scanErr)
		}
		job.Status = OutboxStatus(status)
		claimed = append(claimed, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating claimed outbox rows: %w", err)
	}

	return claimed, nil
}

// MarkOutboxSent marks a claimed sending job as sent.
func (s *Store) MarkOutboxSent(ctx context.Context, q database.Querier, outboxID uuid.UUID) error {
	cmd, err := q.Exec(ctx,
		`UPDATE channel_outbox
		 SET status = $2,
		     sent_at = now(),
		     last_error = NULL,
		     locked_at = NULL,
		     updated_at = now()
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND id = $1
		   AND status = $3`,
		outboxID,
		OutboxStatusSent,
		OutboxStatusSending,
	)
	if err != nil {
		return fmt.Errorf("marking outbox job sent: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrOutboxNotFound
	}
	return nil
}

// MarkOutboxRetry marks a sending job for retry and records the error.
func (s *Store) MarkOutboxRetry(ctx context.Context, q database.Querier, outboxID uuid.UUID, nextAttempt time.Time, lastError string) error {
	if nextAttempt.IsZero() {
		return fmt.Errorf("next attempt timestamp is required")
	}

	cmd, err := q.Exec(ctx,
		`UPDATE channel_outbox
		 SET status = $2,
		     attempt_count = attempt_count + 1,
		     next_attempt_at = $3,
		     last_error = $4,
		     sent_at = NULL,
		     locked_at = NULL,
		     updated_at = now()
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND id = $1
		   AND status = $5`,
		outboxID,
		OutboxStatusPending,
		nextAttempt,
		strings.TrimSpace(lastError),
		OutboxStatusSending,
	)
	if err != nil {
		return fmt.Errorf("marking outbox job retry: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrOutboxNotFound
	}
	return nil
}

// MarkOutboxDead marks a sending job as dead-lettered with the final error.
func (s *Store) MarkOutboxDead(ctx context.Context, q database.Querier, outboxID uuid.UUID, lastError string) error {
	cmd, err := q.Exec(ctx,
		`UPDATE channel_outbox
		 SET status = $2,
		     attempt_count = attempt_count + 1,
		     last_error = $3,
		     locked_at = NULL,
		     updated_at = now()
		 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		   AND id = $1
		   AND status = $4`,
		outboxID,
		OutboxStatusDead,
		strings.TrimSpace(lastError),
		OutboxStatusSending,
	)
	if err != nil {
		return fmt.Errorf("marking outbox job dead: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrOutboxNotFound
	}
	return nil
}

// RecoverStaleSending resets stale sending jobs back to pending for re-claim.
func (s *Store) RecoverStaleSending(ctx context.Context, q database.Querier, staleBefore time.Time, limit int) ([]ChannelOutbox, error) {
	if staleBefore.IsZero() {
		staleBefore = time.Now().UTC()
	}
	if limit <= 0 {
		limit = 1
	}

	rows, err := q.Query(ctx,
		`WITH stale AS (
			SELECT id
			FROM channel_outbox
			WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
			  AND status = $1
			  AND locked_at IS NOT NULL
			  AND locked_at < $2
			ORDER BY locked_at ASC
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE channel_outbox outbox
		SET status = $4,
		    locked_at = NULL,
		    updated_at = now()
		FROM stale
		WHERE outbox.id = stale.id
		RETURNING outbox.id, outbox.tenant_id, outbox.channel_message_id, outbox.provider, outbox.recipient_id,
		          outbox.payload, outbox.status, outbox.attempt_count, outbox.max_attempts, outbox.next_attempt_at,
		          outbox.last_error, outbox.locked_at, outbox.sent_at, outbox.created_at, outbox.updated_at`,
		OutboxStatusSending,
		staleBefore,
		limit,
		OutboxStatusPending,
	)
	if err != nil {
		return nil, fmt.Errorf("recovering stale outbox jobs: %w", err)
	}
	defer rows.Close()

	recovered := make([]ChannelOutbox, 0)
	for rows.Next() {
		var job ChannelOutbox
		var status string
		if scanErr := rows.Scan(
			&job.ID,
			&job.TenantID,
			&job.ChannelMessageID,
			&job.Provider,
			&job.RecipientID,
			&job.Payload,
			&status,
			&job.AttemptCount,
			&job.MaxAttempts,
			&job.NextAttemptAt,
			&job.LastError,
			&job.LockedAt,
			&job.SentAt,
			&job.CreatedAt,
			&job.UpdatedAt,
		); scanErr != nil {
			return nil, fmt.Errorf("scanning recovered outbox row: %w", scanErr)
		}
		job.Status = OutboxStatus(status)
		recovered = append(recovered, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating recovered outbox rows: %w", err)
	}

	return recovered, nil
}
