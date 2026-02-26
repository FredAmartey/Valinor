package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupExchangeTest(t *testing.T) (*Handler, *rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-kid"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	t.Cleanup(jwksSrv.Close)

	tokenSvc := NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)

	h := NewHandler(HandlerConfig{
		TokenSvc:   tokenSvc,
		StateStore: NewStateStore([]byte("test-signing-key-must-be-32-chars!!"), 10*time.Minute),
	})
	h.idTokenValidator = NewIDTokenValidator(IDTokenValidatorConfig{
		JWKSUrl:  jwksSrv.URL,
		Issuer:   "https://clerk.example.com",
		Audience: "client_123",
		CacheTTL: 1 * time.Hour,
	})

	return h, priv, kid
}

func TestHandleExchange_MissingBody(t *testing.T) {
	h, _, _ := setupExchangeTest(t)

	req := httptest.NewRequest("POST", "/auth/exchange", nil)
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleExchange_InvalidToken(t *testing.T) {
	h, _, _ := setupExchangeTest(t)

	body, _ := json.Marshal(map[string]string{"id_token": "invalid.jwt.token"})
	req := httptest.NewRequest("POST", "/auth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleExchange_ValidToken_NoStore(t *testing.T) {
	h, priv, kid := setupExchangeTest(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss":   "https://clerk.example.com",
		"aud":   "client_123",
		"sub":   "user_abc",
		"email": "turgon@gondolin.fc",
		"name":  "Turgon",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	body, _ := json.Marshal(map[string]string{"id_token": tok})
	req := httptest.NewRequest("POST", "/auth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	// Without a store, user lookup fails → 503
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleExchange_NotConfigured(t *testing.T) {
	tokenSvc := NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)
	h := NewHandler(HandlerConfig{
		TokenSvc:   tokenSvc,
		StateStore: NewStateStore([]byte("test-signing-key-must-be-32-chars!!"), 10*time.Minute),
	})
	// No idTokenValidator set

	body, _ := json.Marshal(map[string]string{"id_token": "some.jwt.token"})
	req := httptest.NewRequest("POST", "/auth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
