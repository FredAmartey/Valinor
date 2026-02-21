package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type valinorClaims struct {
	jwt.RegisteredClaims
	UserID      string   `json:"uid"`
	TenantID    string   `json:"tid"`
	Email       string   `json:"email,omitempty"`
	DisplayName string   `json:"name,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Departments []string `json:"depts,omitempty"`
	TokenType   string   `json:"type"`
}

// TokenService handles JWT creation and validation.
type TokenService struct {
	signingKey         []byte
	issuer             string
	expiryHours        int
	refreshExpiryHours int
}

func NewTokenService(signingKey, issuer string, expiryHours, refreshExpiryHours int) *TokenService {
	return &TokenService{
		signingKey:         []byte(signingKey),
		issuer:             issuer,
		expiryHours:        expiryHours,
		refreshExpiryHours: refreshExpiryHours,
	}
}

func (s *TokenService) CreateAccessToken(identity *Identity) (string, error) {
	return s.createToken(identity, "access", s.expiryHours)
}

func (s *TokenService) CreateRefreshToken(identity *Identity) (string, error) {
	return s.createToken(identity, "refresh", s.refreshExpiryHours)
}

func (s *TokenService) createToken(identity *Identity, tokenType string, expiryHours int) (string, error) {
	now := time.Now()

	claims := valinorClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   identity.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expiryHours) * time.Hour)),
		},
		UserID:      identity.UserID,
		TenantID:    identity.TenantID,
		Email:       identity.Email,
		DisplayName: identity.DisplayName,
		Roles:       identity.Roles,
		Departments: identity.Departments,
		TokenType:   tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.signingKey)
}

func (s *TokenService) ValidateToken(tokenString string) (*Identity, error) {
	token, err := jwt.ParseWithClaims(tokenString, &valinorClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signingKey, nil
	}, jwt.WithIssuer(s.issuer))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	claims, ok := token.Claims.(*valinorClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	return &Identity{
		UserID:      claims.UserID,
		TenantID:    claims.TenantID,
		Email:       claims.Email,
		DisplayName: claims.DisplayName,
		Roles:       claims.Roles,
		Departments: claims.Departments,
		TokenType:   claims.TokenType,
	}, nil
}
