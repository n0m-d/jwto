package app

import (
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseClaimValue(t *testing.T) {
	tests := []struct {
		in   string
		want interface{}
	}{
		{"admin", "admin"},
		{"true", true},
		{"false", false},
		{"null", nil},
		{"1999999999", int64(1999999999)},
		{"3.14", 3.14},
		{`"true"`, "true"},
		{`'false'`, "false"},
		{`"123"`, "123"},
		{"  true  ", true},
		{"", ""},
	}

	for _, tt := range tests {
		got := ParseClaimValue(tt.in)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseClaimValue(%q) = %#v (%T), want %#v (%T)", tt.in, got, got, tt.want, tt.want)
		}
	}
}

func TestTamperClaims(t *testing.T) {
	tests := []struct {
		name         string
		claims       jwt.MapClaims
		customClaims map[string]string
		claimsJSON   string
		deleteClaims []string
		wantClaims   jwt.MapClaims
		wantErr      bool
	}{
		{
			name:         "add string claim",
			claims:       jwt.MapClaims{"sub": "1234567890", "name": "John Doe"},
			customClaims: map[string]string{"role": "admin"},
			wantClaims:   jwt.MapClaims{"sub": "1234567890", "name": "John Doe", "role": "admin"},
		},
		{
			name:         "infer bool and int",
			claims:       jwt.MapClaims{"sub": "user"},
			customClaims: map[string]string{"admin": "true", "exp": "1999999999"},
			wantClaims:   jwt.MapClaims{"sub": "user", "admin": true, "exp": int64(1999999999)},
		},
		{
			name:         "force string with quotes",
			claims:       jwt.MapClaims{"sub": "user"},
			customClaims: map[string]string{"admin": `"true"`},
			wantClaims:   jwt.MapClaims{"sub": "user", "admin": "true"},
		},
		{
			name:         "claims-json typed values",
			claims:       jwt.MapClaims{"sub": "user"},
			claimsJSON:   `{"admin":true,"roles":["a","b"],"n":1}`,
			wantClaims:   jwt.MapClaims{"sub": "user", "admin": true, "roles": []interface{}{"a", "b"}, "n": float64(1)},
		},
		{
			name:         "cli claims override claims-json",
			claims:       jwt.MapClaims{"sub": "user"},
			claimsJSON:   `{"admin":false}`,
			customClaims: map[string]string{"admin": "true"},
			wantClaims:   jwt.MapClaims{"sub": "user", "admin": true},
		},
		{
			name:         "delete claims",
			claims:       jwt.MapClaims{"sub": "1234567890", "name": "John Doe", "exp": "1234567890"},
			deleteClaims: []string{"exp"},
			wantClaims:   jwt.MapClaims{"sub": "1234567890", "name": "John Doe"},
		},
		{
			name:         "add and delete claims",
			claims:       jwt.MapClaims{"sub": "1234567890", "name": "John Doe"},
			customClaims: map[string]string{"role": "admin"},
			deleteClaims: []string{"name"},
			wantClaims:   jwt.MapClaims{"sub": "1234567890", "role": "admin"},
		},
		{
			name:       "invalid claims-json",
			claims:     jwt.MapClaims{"sub": "user"},
			claimsJSON: `["not","object"]`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy claims so mutations don't leak across tests unexpectedly.
			base := jwt.MapClaims{}
			for k, v := range tt.claims {
				base[k] = v
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, base)

			gotClaims, err := TamperClaims(token, tt.customClaims, tt.deleteClaims, tt.claimsJSON)
			if (err != nil) != tt.wantErr {
				t.Fatalf("TamperClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			for k, v := range tt.wantClaims {
				if !reflect.DeepEqual(gotClaims[k], v) {
					t.Errorf("claim %s = %#v (%T), want %#v (%T)", k, gotClaims[k], gotClaims[k], v, v)
				}
			}
			for _, claim := range tt.deleteClaims {
				if _, exists := gotClaims[claim]; exists {
					t.Errorf("claim %s should be deleted", claim)
				}
			}
		})
	}
}

func TestGenerateUnsignedToken(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	_, unsignedToken, err := GenerateUnsignedToken(token, Algnone, claims)
	if err != nil {
		t.Fatalf("GenerateUnsignedToken() error = %v", err)
	}
	if unsignedToken == "" {
		t.Fatal("GenerateUnsignedToken() returned empty string")
	}
	if unsignedToken[len(unsignedToken)-1] != '.' {
		t.Fatal("GenerateUnsignedToken() should end with a dot")
	}
}
