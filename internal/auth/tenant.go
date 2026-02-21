package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantResolver resolves tenant IDs from HTTP request hostnames.
type TenantResolver struct {
	pool       *pgxpool.Pool
	baseDomain string
}

func NewTenantResolver(pool *pgxpool.Pool, baseDomain string) *TenantResolver {
	return &TenantResolver{pool: pool, baseDomain: baseDomain}
}

// ResolveFromRequest extracts the tenant slug from the request's Host header
// and looks up the corresponding tenant ID.
func (tr *TenantResolver) ResolveFromRequest(ctx context.Context, r *http.Request) (string, error) {
	slug, err := tr.extractSlug(r.Host)
	if err != nil {
		return "", err
	}

	var tenantID string
	err = tr.pool.QueryRow(ctx,
		"SELECT id FROM tenants WHERE slug = $1",
		slug,
	).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("%w: slug %q", ErrTenantNotFound, slug)
		}
		return "", fmt.Errorf("querying tenant: %w", err)
	}

	return tenantID, nil
}

// extractSlug parses the subdomain from a host string.
// Expects format: <slug>.<baseDomain> (e.g. "chelsea-fc.valinor.example.com").
func (tr *TenantResolver) extractSlug(host string) (string, error) {
	// Strip port if present
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port present
		hostname = host
	}

	if !strings.HasSuffix(hostname, "."+tr.baseDomain) {
		return "", fmt.Errorf("%w: host %q does not match base domain %q", ErrTenantNotFound, hostname, tr.baseDomain)
	}

	slug := strings.TrimSuffix(hostname, "."+tr.baseDomain)
	if slug == "" || strings.Contains(slug, ".") {
		return "", fmt.Errorf("%w: invalid slug in host %q", ErrTenantNotFound, hostname)
	}

	return slug, nil
}
