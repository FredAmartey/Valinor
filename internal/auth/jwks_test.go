package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	defer srv.Close()

	client := NewJWKSClient(srv.URL, 1*time.Hour)
	ctx := context.Background()

	t.Run("fetches key on first call", func(t *testing.T) {
		key, err := client.GetKey(ctx, kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, int32(1), calls.Load())
	})

	t.Run("returns cached key on second call", func(t *testing.T) {
		key, err := client.GetKey(ctx, kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, int32(1), calls.Load(), "should not re-fetch")
	})

	t.Run("unknown kid triggers refresh", func(t *testing.T) {
		_, err := client.GetKey(ctx, "unknown-kid")
		assert.Error(t, err)
		assert.Equal(t, int32(2), calls.Load(), "should have re-fetched once")
	})
}

func TestJWKSClient_CacheExpiry(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-key-1"
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildJWKS(t, kid, &priv.PublicKey))
	}))
	defer srv.Close()

	// Very short TTL to test expiry
	client := NewJWKSClient(srv.URL, 1*time.Millisecond)
	ctx := context.Background()

	_, err = client.GetKey(ctx, kid)
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load())

	time.Sleep(5 * time.Millisecond)

	_, err = client.GetKey(ctx, kid)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "should re-fetch after TTL expiry")
}
