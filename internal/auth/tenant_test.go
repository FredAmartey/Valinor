package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantResolver_ExtractSlugFromOrigin(t *testing.T) {
	tr := &TenantResolver{baseDomain: "heimdall.example.com"}

	tests := []struct {
		name    string
		origin  string
		want    string
		wantErr bool
	}{
		{
			name:   "valid https origin",
			origin: "https://chelsea-fc.heimdall.example.com",
			want:   "chelsea-fc",
		},
		{
			name:   "valid https origin with port",
			origin: "https://chelsea-fc.heimdall.example.com:3000",
			want:   "chelsea-fc",
		},
		{
			name:   "valid http origin",
			origin: "http://chelsea-fc.heimdall.example.com",
			want:   "chelsea-fc",
		},
		{
			name:    "bare base domain",
			origin:  "https://heimdall.example.com",
			wantErr: true,
		},
		{
			name:    "wrong base domain",
			origin:  "https://chelsea-fc.other.com",
			wantErr: true,
		},
		{
			name:    "empty origin",
			origin:  "",
			wantErr: true,
		},
		{
			name:    "not a url",
			origin:  "not-a-url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tr.extractSlugFromOrigin(tt.origin)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTenantResolver_ExtractSlug(t *testing.T) {
	tr := &TenantResolver{baseDomain: "heimdall.example.com"}

	tests := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{
			name: "valid subdomain",
			host: "chelsea-fc.heimdall.example.com",
			want: "chelsea-fc",
		},
		{
			name: "valid subdomain with port",
			host: "chelsea-fc.heimdall.example.com:8080",
			want: "chelsea-fc",
		},
		{
			name:    "bare base domain",
			host:    "heimdall.example.com",
			wantErr: true,
		},
		{
			name:    "wrong base domain",
			host:    "chelsea-fc.other.com",
			wantErr: true,
		},
		{
			name:    "nested subdomain",
			host:    "deep.chelsea-fc.heimdall.example.com",
			wantErr: true,
		},
		{
			name:    "empty host",
			host:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tr.extractSlug(tt.host)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
