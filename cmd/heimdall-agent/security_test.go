package main

import "testing"

func TestValidateOpenClawURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rawURL      string
		allowRemote bool
		wantErr     bool
	}{
		{
			name:    "localhost allowed",
			rawURL:  "http://localhost:8081",
			wantErr: false,
		},
		{
			name:    "ipv4 loopback allowed",
			rawURL:  "http://127.0.0.1:8081",
			wantErr: false,
		},
		{
			name:    "ipv6 loopback allowed",
			rawURL:  "http://[::1]:8081",
			wantErr: false,
		},
		{
			name:    "remote blocked by default",
			rawURL:  "http://example.com:8081",
			wantErr: true,
		},
		{
			name:        "remote allowed with override",
			rawURL:      "https://openclaw.internal",
			allowRemote: true,
			wantErr:     false,
		},
		{
			name:    "malformed url rejected",
			rawURL:  ":/bad",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateOpenClawURL(tt.rawURL, tt.allowRemote)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q", tt.rawURL)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error for %q, got %v", tt.rawURL, err)
			}
		})
	}
}
