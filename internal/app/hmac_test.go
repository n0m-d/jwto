package app

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyHMAC_RejectsAlgorithmMismatch(t *testing.T) {
	const secret = "test-secret"

	tests := []struct {
		name       string
		signMethod jwt.SigningMethod
		verifyAlg  string
		want       bool
	}{
		{
			name:       "HS256 matches",
			signMethod: jwt.SigningMethodHS256,
			verifyAlg:  "HS256",
			want:       true,
		},
		{
			name:       "HS256 verified as HS384 fails",
			signMethod: jwt.SigningMethodHS256,
			verifyAlg:  "HS384",
			want:       false,
		},
		{
			name:       "HS256 verified as HS512 fails",
			signMethod: jwt.SigningMethodHS256,
			verifyAlg:  "HS512",
			want:       false,
		},
		{
			name:       "HS384 matches",
			signMethod: jwt.SigningMethodHS384,
			verifyAlg:  "HS384",
			want:       true,
		},
		{
			name:       "HS384 verified as HS256 fails",
			signMethod: jwt.SigningMethodHS384,
			verifyAlg:  "HS256",
			want:       false,
		},
		{
			name:       "HS384 verified as HS512 fails",
			signMethod: jwt.SigningMethodHS384,
			verifyAlg:  "HS512",
			want:       false,
		},
		{
			name:       "HS512 matches",
			signMethod: jwt.SigningMethodHS512,
			verifyAlg:  "HS512",
			want:       true,
		},
		{
			name:       "HS512 verified as HS256 fails",
			signMethod: jwt.SigningMethodHS512,
			verifyAlg:  "HS256",
			want:       false,
		},
		{
			name:       "HS512 verified as HS384 fails",
			signMethod: jwt.SigningMethodHS512,
			verifyAlg:  "HS384",
			want:       false,
		},
		{
			name:       "empty algorithm fails",
			signMethod: jwt.SigningMethodHS256,
			verifyAlg:  "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := makeTestToken(t, tt.signMethod, secret)
			got, err := VerifyHMAC(token, secret, tt.verifyAlg)
			if err != nil && err.Error() != "algorithm is required" {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Fatalf("VerifyHMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func makeTestToken(
	t *testing.T,
	method jwt.SigningMethod,
	secret string,
) string {
	t.Helper()

	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"sub": "test-user",
		"foo": "bar",
	})

	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}

	return signed
}
