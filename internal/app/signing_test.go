package app

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestResolveSigningMethod(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1"})

	method, err := ResolveSigningMethod("", token)
	if err != nil || method.Alg() != "HS256" {
		t.Fatalf("default alg: got %v err %v", method, err)
	}

	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		method, err = ResolveSigningMethod(alg, token)
		if err != nil || method.Alg() != alg {
			t.Fatalf("ResolveSigningMethod(%q) = %v err %v", alg, method, err)
		}
	}

	if _, err := ResolveSigningMethod("RS256", token); err == nil {
		t.Fatal("expected error for RS256")
	}
}

func TestSignToken(t *testing.T) {
	secret := "password"
	original := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user"})
	originalRaw, err := original.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	original, _, err = jwt.NewParser().ParseUnverified(originalRaw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	original.Raw = originalRaw

	tests := []struct {
		name string
		alg  string
	}{
		{name: "default", alg: ""},
		{name: "hs256", alg: "HS256"},
		{name: "hs384", alg: "HS384"},
		{name: "hs512", alg: "HS512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newToken, signed, err := SignToken(original, secret, tt.alg, map[string]string{"role": "admin"}, nil, "", false)
			if err != nil {
				t.Fatalf("SignToken() error = %v", err)
			}

			wantAlg := tt.alg
			if wantAlg == "" {
				wantAlg = "HS256"
			}

			ok, err := VerifyHMAC(signed, secret, wantAlg)
			if err != nil || !ok {
				t.Fatalf("VerifyHMAC() = %v err %v", ok, err)
			}

			claims := newToken.Claims.(jwt.MapClaims)
			if claims["role"] != "admin" {
				t.Fatalf("role claim = %v", claims["role"])
			}
		})
	}
}

func TestVerifyHMAC(t *testing.T) {
	secret := "test-secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1"})
	raw, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyHMAC(raw, secret, "HS256")
	if err != nil || !ok {
		t.Fatalf("VerifyHMAC() valid token = %v err %v", ok, err)
	}

	ok, err = VerifyHMAC(raw, "wrong", "HS256")
	if err != nil || ok {
		t.Fatalf("VerifyHMAC() wrong secret = %v err %v", ok, err)
	}
}

func TestVerifyTokenSecret(t *testing.T) {
	secret := "test-secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1"})
	raw, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	parsed.Raw = raw

	ok, err := VerifyTokenSecret(parsed, secret, "")
	if err != nil || !ok {
		t.Fatalf("VerifyTokenSecret() valid = %v err %v", ok, err)
	}

	ok, err = VerifyTokenSecret(parsed, "wrong", "")
	if err != nil || ok {
		t.Fatalf("VerifyTokenSecret() wrong secret = %v err %v", ok, err)
	}
}

func TestSignTokenVerifyBeforeTamper(t *testing.T) {
	secret := "password"
	original := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user"})
	raw, err := original.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	parsed.Raw = raw

	_, _, err = SignToken(parsed, "wrong-secret", "", nil, nil, "", true)
	if err == nil {
		t.Fatal("expected error when secret does not match")
	}

	_, _, err = SignToken(parsed, "wrong-secret", "", nil, nil, "", false)
	if err != nil {
		t.Fatalf("expected sign without verify to succeed, got %v", err)
	}
}
