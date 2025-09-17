package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantKey     string
		wantErr     error
	}{
		{
			name:        "valid authorization header",
			headerValue: "ApiKey secret123",
			wantKey:     "secret123",
			wantErr:     nil,
		},
		{
			name:        "missing authorization header",
			headerValue: "",
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header: no space",
			headerValue: "ApiKeysecret123",
			wantKey:     "",
			wantErr:     ErrMalformedAuthHeader,
		},
		{
			name:        "malformed header: wrong scheme",
			headerValue: "Bearer secret123",
			wantKey:     "",
			wantErr:     ErrMalformedAuthHeader,
		},
		{
			name:        "missing key part (empty after space)",
			headerValue: "ApiKey ",
			wantKey:     "",  // empty string for key
			wantErr:     nil, // no error in this case
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.headerValue != "" {
				headers.Set("Authorization", tc.headerValue)
			}
			gotKey, err := GetAPIKey(headers)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if gotKey != tc.wantKey {
					t.Errorf("expected key %q, got %q", tc.wantKey, gotKey)
				}
			}
		})
	}
}
