package channels

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const credentialCiphertextPrefix = "enc:v1:"

// CredentialCrypto encrypts/decrypts provider credential fields.
type CredentialCrypto struct {
	aead cipher.AEAD
	rand io.Reader
}

// NewCredentialCrypto creates a credential crypto helper from a base64-encoded 32-byte key.
func NewCredentialCrypto(base64Key string) (*CredentialCrypto, error) {
	trimmed := strings.TrimSpace(base64Key)
	if trimmed == "" {
		return nil, ErrProviderCredentialCipherRequired
	}

	key, err := decodeCredentialKey(trimmed)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, ErrProviderCredentialKeyInvalid
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: new cipher: %v", ErrProviderCredentialKeyInvalid, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: new gcm: %v", ErrProviderCredentialKeyInvalid, err)
	}

	return &CredentialCrypto{aead: aead, rand: rand.Reader}, nil
}

// IsEncryptedCredentialValue reports whether value looks like encrypted credential ciphertext.
func IsEncryptedCredentialValue(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), credentialCiphertextPrefix)
}

// Encrypt encrypts a plaintext credential value and prefixes it with version marker.
func (c *CredentialCrypto) Encrypt(plaintext string) (string, error) {
	if c == nil || c.aead == nil {
		return "", ErrProviderCredentialCipherRequired
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(c.rand, nonce); err != nil {
		return "", fmt.Errorf("%w: generating nonce: %v", ErrProviderCredentialEncryptFailed, err)
	}

	ciphertext := c.aead.Seal(nil, nonce, []byte(plaintext), nil)
	payload := append(nonce, ciphertext...)
	return credentialCiphertextPrefix + base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt decrypts an encrypted credential value with expected version prefix.
func (c *CredentialCrypto) Decrypt(value string) (string, error) {
	if c == nil || c.aead == nil {
		return "", ErrProviderCredentialCipherRequired
	}
	if !IsEncryptedCredentialValue(value) {
		return "", fmt.Errorf("%w: value is not encrypted", ErrProviderCredentialDecryptFailed)
	}

	encoded := strings.TrimPrefix(strings.TrimSpace(value), credentialCiphertextPrefix)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("%w: decoding payload: %v", ErrProviderCredentialDecryptFailed, err)
	}

	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("%w: payload too short", ErrProviderCredentialDecryptFailed)
	}

	nonce := raw[:nonceSize]
	ciphertext := raw[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("%w: opening ciphertext: %v", ErrProviderCredentialDecryptFailed, err)
	}
	return string(plaintext), nil
}

func decodeCredentialKey(base64Key string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Key)
	if err == nil {
		return decoded, nil
	}

	decoded, rawErr := base64.RawStdEncoding.DecodeString(base64Key)
	if rawErr == nil {
		return decoded, nil
	}

	return nil, fmt.Errorf("%w: invalid base64 key", ErrProviderCredentialKeyInvalid)
}
