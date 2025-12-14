package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers     http.Header
		expectedKey string
		expectedErr error
		errContains string
	}{
		"valid api key": {
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		"no authorization header": {
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		"empty authorization header": {
			headers:     http.Header{"Authorization": []string{""}},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		"malformed header - wrong prefix": {
			headers:     http.Header{"Authorization": []string{"Bearer my-token"}},
			expectedKey: "",
			errContains: "malformed authorization header",
		},
		"malformed header - missing key": {
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			errContains: "malformed authorization header",
		},
		"malformed header - only prefix no space": {
			headers:     http.Header{"Authorization": []string{"ApiKeyNoSpace"}},
			expectedKey: "",
			errContains: "malformed authorization header",
		},
		"valid api key with extra parts": {
			headers:     http.Header{"Authorization": []string{"ApiKey key-part extra-part"}},
			expectedKey: "key-part",
			expectedErr: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}

			if tc.expectedErr != nil {
				if err != tc.expectedErr {
					t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else if tc.errContains != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.errContains)
				} else if err.Error() != tc.errContains {
					t.Errorf("expected error %q, got %q", tc.errContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
