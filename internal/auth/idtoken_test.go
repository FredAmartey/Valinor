package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupIDTokenValidator(t *testing.T) (*IDTokenValidator, *rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-kid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	t.Cleanup(srv.Close)

	v := NewIDTokenValidator(IDTokenValidatorConfig{
		JWKSUrl:  srv.URL,
		Issuer:   "https://clerk.example.com",
		Audience: "client_123",
		CacheTTL: 1 * time.Hour,
	})
	return v, priv, kid
}

func signIDToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	require.NoError(t, err)
	return signed
}

func TestIDTokenValidator_ValidToken(t *testing.T) {
	v, priv, kid := setupIDTokenValidator(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss":   "https://clerk.example.com",
		"aud":   "client_123",
		"sub":   "user_abc",
		"email": "turgon@gondolin.fc",
		"name":  "Turgon",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	info, err := v.Validate(tok)
	require.NoError(t, err)
	assert.Equal(t, "https://clerk.example.com", info.Issuer)
	assert.Equal(t, "user_abc", info.Subject)
	assert.Equal(t, "turgon@gondolin.fc", info.Email)
	assert.Equal(t, "Turgon", info.Name)
}

func TestIDTokenValidator_ExpiredToken(t *testing.T) {
	v, priv, kid := setupIDTokenValidator(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://clerk.example.com",
		"aud": "client_123",
		"sub": "user_abc",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	})

	_, err := v.Validate(tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestIDTokenValidator_WrongIssuer(t *testing.T) {
	v, priv, kid := setupIDTokenValidator(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://evil.example.com",
		"aud": "client_123",
		"sub": "user_abc",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	_, err := v.Validate(tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestIDTokenValidator_WrongAudience(t *testing.T) {
	v, priv, kid := setupIDTokenValidator(t)

	tok := signIDToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://clerk.example.com",
		"aud": "wrong_client",
		"sub": "user_abc",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	_, err := v.Validate(tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}
