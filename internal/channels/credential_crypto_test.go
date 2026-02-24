package channels

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialCrypto_NewRejectsInvalidBase64(t *testing.T) {
	_, err := NewCredentialCrypto("%%%not-base64%%")
	require.Error(t, err)
}

func TestCredentialCrypto_NewRejectsWrongKeyLength(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString([]byte("short-key"))
	_, err := NewCredentialCrypto(shortKey)
	require.Error(t, err)
}

func TestCredentialCrypto_EncryptDecryptRoundTrip(t *testing.T) {
	crypto, err := NewCredentialCrypto("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	require.NoError(t, err)

	ciphertext, err := crypto.Encrypt("secret-value")
	require.NoError(t, err)
	require.True(t, IsEncryptedCredentialValue(ciphertext))
	require.True(t, strings.HasPrefix(ciphertext, credentialCiphertextPrefix))

	plaintext, err := crypto.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "secret-value", plaintext)
}

func TestCredentialCrypto_DecryptWithWrongKeyFails(t *testing.T) {
	cryptoA, err := NewCredentialCrypto("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	require.NoError(t, err)
	cryptoB, err := NewCredentialCrypto("ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=")
	require.NoError(t, err)

	ciphertext, err := cryptoA.Encrypt("secret-value")
	require.NoError(t, err)

	_, err = cryptoB.Decrypt(ciphertext)
	require.Error(t, err)
}

func TestCredentialCrypto_IsEncryptedCredentialValue(t *testing.T) {
	assert.False(t, IsEncryptedCredentialValue(""))
	assert.False(t, IsEncryptedCredentialValue("legacy-plaintext"))
	assert.True(t, IsEncryptedCredentialValue("enc:v1:anything"))
}
