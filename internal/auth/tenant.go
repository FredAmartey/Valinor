package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

// ResolveBySlug looks up the tenant ID for a given slug.
func (tr *TenantResolver) ResolveBySlug(ctx context.Context, slug string) (string, error) {
	if slug == "" {
		return "", fmt.Errorf("%w: empty slug", ErrTenantNotFound)
	}

	var tenantID string
	err := tr.pool.QueryRow(ctx,
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

// ResolveFromRequest extracts the tenant slug from the request's Host header
// and looks up the corresponding tenant ID.
func (tr *TenantResolver) ResolveFromRequest(ctx context.Context, r *http.Request) (string, error) {
	slug, err := tr.extractSlug(r.Host)
	if err != nil {
		return "", err
	}
	return tr.ResolveBySlug(ctx, slug)
}

// ResolveFromOrigin extracts the tenant slug from an Origin header URL
// (e.g. "https://gondolin.valinor.example.com") and looks up the tenant ID.
func (tr *TenantResolver) ResolveFromOrigin(ctx context.Context, origin string) (string, error) {
	slug, err := tr.extractSlugFromOrigin(origin)
	if err != nil {
		return "", err
	}
	return tr.ResolveBySlug(ctx, slug)
}

// extractSlugFromOrigin parses the subdomain from an Origin URL string.
func (tr *TenantResolver) extractSlugFromOrigin(origin string) (string, error) {
	if origin == "" {
		return "", fmt.Errorf("%w: empty origin", ErrTenantNotFound)
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: invalid origin %q", ErrTenantNotFound, origin)
	}
	return tr.extractSlug(u.Host)
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
