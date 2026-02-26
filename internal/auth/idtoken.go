package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IDTokenValidatorConfig holds configuration for validating external id_tokens.
type IDTokenValidatorConfig struct {
	JWKSUrl  string
	Issuer   string
	Audience string
	CacheTTL time.Duration
}

// IDTokenValidator validates external OIDC id_tokens using JWKS.
type IDTokenValidator struct {
	jwks     *JWKSClient
	issuer   string
	audience string
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
	}
}

// Validate parses and validates an external id_token.
// Returns the user info extracted from the verified claims.
func (v *IDTokenValidator) Validate(tokenString string) (*OIDCUserInfo, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		return v.jwks.GetKey(kid)
	},
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("validating id_token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
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
