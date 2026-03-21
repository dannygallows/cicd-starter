package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		want          string
		wantErrString string
	}{
		{
			name: "Valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-key-12345"},
			},
			want:          "secret-key-12345",
			wantErrString: "",
		},
		{
			name:          "No Authorization header",
			headers:       http.Header{},
			want:          "",
			wantErrString: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "Malformed: Missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			want:          "",
			wantErrString: "malformed authorization header",
		},
		{
			name: "Malformed: Only prefix provided",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:          "",
			wantErrString: "malformed authorization header",
		},
		{
			name: "Malformed: Empty string",
			headers: http.Header{
				"Authorization": []string{""},
			},
			want:          "",
			wantErrString: ErrNoAuthHeaderIncluded.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			// Check if error matches expectation
			if (err != nil) && err.Error() != tt.wantErrString {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErrString)
				return
			}
			if err == nil && tt.wantErrString != "" {
				t.Errorf("GetAPIKey() expected error %v, but got none", tt.wantErrString)
				return
			}

			// Check if returned key matches expectation
			if got != tt.want {
				t.Errorf("GetAPIKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}
