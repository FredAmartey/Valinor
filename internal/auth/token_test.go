package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
)

func TestTokenService_CreateAndValidate(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	identity := &auth.Identity{
		UserID:      "user-123",
		TenantID:    "tenant-456",
		Email:       "scout@chelsea.com",
		DisplayName: "Scout A",
		Roles:       []string{"standard_user"},
		Departments: []string{"dept-scouting"},
	}

	token, err := svc.CreateAccessToken(identity)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate the token
	got, err := svc.ValidateToken(token)
	require.NoError(t, err)

	assert.Equal(t, identity.UserID, got.UserID)
	assert.Equal(t, identity.TenantID, got.TenantID)
	assert.Equal(t, identity.Email, got.Email)
	assert.Equal(t, identity.Roles, got.Roles)
	assert.Equal(t, identity.Departments, got.Departments)
}

func TestTokenService_CreateRefreshToken(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
	}

	refreshToken, err := svc.CreateRefreshToken(identity)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	got, err := svc.ValidateToken(refreshToken)
	require.NoError(t, err)
	assert.Equal(t, "user-123", got.UserID)
	assert.Equal(t, "refresh", got.TokenType)
}

func TestTokenService_ExpiredToken(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 0, 0) // 0 hours = expires immediately

	identity := &auth.Identity{UserID: "user-123", TenantID: "tenant-456"}

	token, err := svc.CreateAccessToken(identity)
	require.NoError(t, err)

	// Token should be expired
	time.Sleep(time.Second)
	_, err = svc.ValidateToken(token)
	assert.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestTokenService_InvalidSignature(t *testing.T) {
	svc1 := auth.NewTokenService("signing-key-one-must-be-32-chars!!", "valinor", 24, 168)
	svc2 := auth.NewTokenService("signing-key-two-must-be-32-chars!!", "valinor", 24, 168)

	identity := &auth.Identity{UserID: "user-123", TenantID: "tenant-456"}

	token, err := svc1.CreateAccessToken(identity)
	require.NoError(t, err)

	_, err = svc2.ValidateToken(token)
	assert.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenService_WrongIssuer(t *testing.T) {
	key := "test-signing-key-must-be-32-chars!!"
	svc1 := auth.NewTokenService(key, "valinor", 24, 168)
	svc2 := auth.NewTokenService(key, "other-service", 24, 168)

	identity := &auth.Identity{UserID: "user-123", TenantID: "tenant-456"}

	token, err := svc1.CreateAccessToken(identity)
	require.NoError(t, err)

	_, err = svc2.ValidateToken(token)
	assert.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenService_MalformedToken(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	_, err := svc.ValidateToken("not.a.jwt")
	assert.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestTokenService_RefreshTokenWithFamilyClaims(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	identity := &auth.Identity{
		UserID:     "user-123",
		TenantID:   "tenant-456",
		FamilyID:   "family-abc",
		Generation: 3,
	}

	token, err := svc.CreateRefreshToken(identity)
	require.NoError(t, err)

	got, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "family-abc", got.FamilyID)
	assert.Equal(t, 3, got.Generation)
	assert.Equal(t, "refresh", got.TokenType)
}

func TestTokenService_LegacyTokenLacksFamilyClaims(t *testing.T) {
	svc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
	}

	token, err := svc.CreateRefreshToken(identity)
	require.NoError(t, err)

	got, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Empty(t, got.FamilyID)
	assert.Equal(t, 0, got.Generation)
}
