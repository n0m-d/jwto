package commands

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/n0m-d/jwto/internal/app"
	"github.com/n0m-d/jwto/internal/ui"
)

// HandleSigning processes the signing command for JWT Token Signing.
func HandleSigning(token *jwt.Token, secret, alg string, claims map[string]string, deleteClaims []string, claimsJSON string, skipVerify bool) error {
	newToken, signedToken, err := app.SignToken(token, secret, alg, claims, deleteClaims, claimsJSON, !skipVerify)
	if err != nil {
		return err
	}

	ui.PrintRawToken(signedToken)
	ui.GenTokenTree(newToken)
	return nil
}
