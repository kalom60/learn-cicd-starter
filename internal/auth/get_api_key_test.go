package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		expectedKey string
		expectedErr error
	}{
		{
			name:        "valid API key",
			header:      "ApiKey my-secret-key",
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "missing authorization header",
			header:      "",
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "wrong authorization scheme",
			header:      "Bearer my-token",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}

			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			key, err := GetAPIKey(headers)

			if tt.expectedErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if key != tt.expectedKey {
					t.Fatalf("expected key %q, got %q", tt.expectedKey, key)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected an error, got nil")
			}

			if err.Error() != tt.expectedErr.Error() {
				t.Fatalf("expected error %q, got %q", tt.expectedErr.Error(), err.Error())
			}
		})
	}
}
