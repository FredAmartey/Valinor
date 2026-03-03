package tenant

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrSlugTaken      = errors.New("tenant slug already in use")
	ErrInvalidSlug    = errors.New("invalid tenant slug")
)

// Tenant represents a tenant in the system.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Stats     *Stats    `json:"stats,omitempty"`
}

// Stats holds aggregate counts for a tenant's resources.
type Stats struct {
	Users       int `json:"users"`
	Departments int `json:"departments"`
	Agents      int `json:"agents"`
	Connectors  int `json:"connectors"`
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

var reservedSlugs = map[string]bool{
	"api": true, "app": true, "www": true, "admin": true,
	"platform": true, "auth": true, "static": true, "assets": true,
}

// GenerateSlug creates a URL-safe slug from a team name.
func GenerateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, slug)
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	slug = strings.Trim(slug, "-")
	if len(slug) < 3 {
		slug = slug + "-team"
	}
	if len(slug) > 63 {
		slug = slug[:63]
	}
	return slug
}

// ValidateSlug checks that a slug conforms to DNS label rules and is not reserved.
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) {
		return fmt.Errorf("%w: must be 3-63 lowercase alphanumeric characters or hyphens, cannot start/end with hyphen", ErrInvalidSlug)
	}
	if reservedSlugs[slug] {
		return fmt.Errorf("%w: %q is reserved", ErrInvalidSlug, slug)
	}
	return nil
}
