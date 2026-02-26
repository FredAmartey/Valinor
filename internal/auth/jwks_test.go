package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: build a minimal JWKS JSON from an RSA public key
func buildJWKS(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	b, err := json.Marshal(jwks)
	require.NoError(t, err)
	return b
}

func TestJWKSClient_GetKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-key-1"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	defer srv.Close()

	client := NewJWKSClient(srv.URL, 1*time.Hour)

	t.Run("fetches key on first call", func(t *testing.T) {
		key, err := client.GetKey(kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 1, calls)
	})

	t.Run("returns cached key on second call", func(t *testing.T) {
		key, err := client.GetKey(kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 1, calls, "should not re-fetch")
	})

	t.Run("unknown kid triggers refresh", func(t *testing.T) {
		_, err := client.GetKey("unknown-kid")
		assert.Error(t, err)
		assert.Equal(t, 2, calls, "should have re-fetched once")
	})
}

func TestJWKSClient_CacheExpiry(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-key-1"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	defer srv.Close()

	// Very short TTL to test expiry
	client := NewJWKSClient(srv.URL, 1*time.Millisecond)

	_, err = client.GetKey(kid)
	require.NoError(t, err)
	assert.Equal(t, 1, calls)

	time.Sleep(5 * time.Millisecond)

	_, err = client.GetKey(kid)
	require.NoError(t, err)
	assert.Equal(t, 2, calls, "should re-fetch after TTL expiry")
}
