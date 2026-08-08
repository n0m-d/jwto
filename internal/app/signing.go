package app

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// SignToken tampers claims and signs the token with the given HMAC secret and algorithm.
// When verify is true, the secret is checked against the original token before tampering.
func SignToken(
	token *jwt.Token,
	secret string,
	alg string,
	customClaims map[string]string,
	deleteClaims []string,
	claimsJSON string,
	verify bool,
) (*jwt.Token, string, error) {
	if secret == "" {
		return nil, "", fmt.Errorf("secret is required")
	}

	if verify {
		ok, err := VerifyTokenSecret(token, secret, "")
		if err != nil {
			return nil, "", fmt.Errorf("verification failed: %w", err)
		}
		if !ok {
			return nil, "", fmt.Errorf("secret does not match token signature")
		}
	}

	method, err := ResolveSigningMethod(alg, token)
	if err != nil {
		return nil, "", fmt.Errorf("resolving algorithm: %w", err)
	}

	claims, err := TamperClaims(token, customClaims, deleteClaims, claimsJSON)
	if err != nil {
		return nil, "", fmt.Errorf("tampering claims: %w", err)
	}

	newToken := jwt.NewWithClaims(method, claims)

	signed, err := newToken.SignedString([]byte(secret))
	if err != nil {
		return nil, "", fmt.Errorf("signing token: %w", err)
	}

	newToken.Raw = signed
	return newToken, signed, nil
}
