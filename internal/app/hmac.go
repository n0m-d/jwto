package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type hmacSigner struct {
	newHash func(key []byte) hash.Hash
}

// HMACSigningMethods maps supported HMAC algorithm names to signing methods.
var HMACSigningMethods = map[string]jwt.SigningMethod{
	"HS256": jwt.SigningMethodHS256,
	"HS384": jwt.SigningMethodHS384,
	"HS512": jwt.SigningMethodHS512,
}

var hmacSigners = map[string]hmacSigner{
	"HS256": {newHash: func(key []byte) hash.Hash { return hmac.New(sha256.New, key) }},
	"HS384": {newHash: func(key []byte) hash.Hash { return hmac.New(sha512.New384, key) }},
	"HS512": {newHash: func(key []byte) hash.Hash { return hmac.New(sha512.New, key) }},
}

// ResolveSigningMethod returns the signing method for the given algorithm name.
// When alg is empty, the token's current algorithm is used if it is a supported HMAC alg.
func ResolveSigningMethod(alg string, token *jwt.Token) (jwt.SigningMethod, error) {
	name := strings.ToUpper(strings.TrimSpace(alg))
	if name == "" {
		if token != nil && token.Method != nil {
			name = token.Method.Alg()
		}
	}

	method, ok := HMACSigningMethods[name]
	if !ok {
		return nil, fmt.Errorf("unsupported signing algorithm %q (supported: HS256, HS384, HS512)", name)
	}

	return method, nil
}

// VerifyHMAC checks whether a token was signed with the given HMAC secret.
func VerifyHMAC(token, secret, alg string) (bool, error) {
	name := strings.ToUpper(strings.TrimSpace(alg))
	if name == "" {
		return false, errors.New("algorithm is required")
	}

	return verifyHMACWithAlg(token, secret, name)
}

// VerifyTokenSecret checks whether the secret matches the token's signature.
// When alg is empty, the token's current algorithm is used.
func VerifyTokenSecret(token *jwt.Token, secret, alg string) (bool, error) {
	if secret == "" {
		return false, fmt.Errorf("secret is required")
	}
	if token == nil || token.Raw == "" {
		return false, fmt.Errorf("token is required")
	}

	name := strings.ToUpper(strings.TrimSpace(alg))
	if name == "" {
		if token.Method != nil {
			name = token.Method.Alg()
		}
	}

	if _, ok := HMACSigningMethods[name]; !ok {
		return false, fmt.Errorf("unsupported algorithm %q for verification (supported: HS256, HS384, HS512)", name)
	}

	return verifyHMACWithAlg(token.Raw, secret, name)
}

func verifyHMACWithAlg(token, secret, name string) (bool, error) {
	signer, ok := hmacSigners[name]
	if !ok {
		return false, fmt.Errorf("unsupported algorithm: %s", name)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, errors.New("invalid token format")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, err
	}

	mac := signer.newHash([]byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	return hmac.Equal(mac.Sum(nil), sig), nil
}
