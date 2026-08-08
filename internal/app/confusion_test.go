package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestConfusionAttackAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	original := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "user"})
	raw, err := original.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	parsed.Raw = raw

	for _, alg := range []string{"", "HS256", "HS384", "HS512"} {
		want := alg
		if want == "" {
			want = "HS256"
		}
		newToken, signed, err := ConfusionAttack(parsed, pemBytes, map[string]string{"admin": "true"}, nil, "", alg)
		if err != nil {
			t.Fatalf("alg %q: %v", alg, err)
		}
		if newToken.Method.Alg() != want {
			t.Fatalf("alg %q: got method %s", alg, newToken.Method.Alg())
		}
		ok, err := VerifyHMAC(signed, string(pemBytes), want)
		if err != nil || !ok {
			t.Fatalf("alg %q: verify = %v err %v", alg, ok, err)
		}
	}

	if _, _, err := ConfusionAttack(parsed, pemBytes, nil, nil, "", "RS256"); err == nil {
		t.Fatal("expected error for RS256")
	}
}
