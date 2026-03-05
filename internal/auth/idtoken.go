package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IDTokenValidatorConfig holds configuration for validating external id_tokens.
type IDTokenValidatorConfig struct {
	JWKSUrl  string
	Issuer   string
	Audience string
	AZP      string
	CacheTTL time.Duration
}

// IDTokenValidator validates external OIDC id_tokens using JWKS.
type IDTokenValidator struct {
	jwks     *JWKSClient
	issuer   string
	audience string
	azp      string
}

// NewIDTokenValidator creates a validator for external id_tokens.
func NewIDTokenValidator(cfg IDTokenValidatorConfig) *IDTokenValidator {
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = 1 * time.Hour
	}
	return &IDTokenValidator{
		jwks:     NewJWKSClient(cfg.JWKSUrl, ttl),
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		azp:      cfg.AZP,
	}
}

// Validate parses and validates an external id_token.
// Returns the user info extracted from the verified claims.
func (v *IDTokenValidator) Validate(ctx context.Context, tokenString string) (*OIDCUserInfo, error) {
	keyFunc := func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		return v.jwks.GetKey(ctx, kid)
	}

	opts := []jwt.ParserOption{
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	token, err := jwt.Parse(tokenString, keyFunc, opts...)
	if err != nil {
		return nil, fmt.Errorf("validating id_token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// When audience validation is skipped, validate azp (authorized party) if configured.
	if v.audience == "" && v.azp != "" {
		azp, _ := claims["azp"].(string)
		if azp != v.azp {
			return nil, fmt.Errorf("azp mismatch: got %q, want %q", azp, v.azp)
		}
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	issuer, _ := claims["iss"].(string)

	return &OIDCUserInfo{
		Issuer:  issuer,
		Subject: sub,
		Email:   email,
		Name:    name,
	}, nil
}
