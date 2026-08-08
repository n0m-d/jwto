package commands

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/n0m-d/jwto/internal/app"
	"github.com/n0m-d/jwto/internal/ui"
)

// HandleConfusion processes the confusion attack command for Algorithm Confusion attacks.
func HandleConfusion(token *jwt.Token, pubKey string, claims map[string]string, deleteClaims []string, claimsJSON, alg string) error {
	if pubKey == "" {
		return fmt.Errorf("public key path is required")
	}

	pubKeyData, err := os.ReadFile(pubKey)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}

	spkiBlock, _ := pem.Decode(pubKeyData)
	if spkiBlock == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing public key: %w", err)
	}

	if _, ok := pubInterface.(*rsa.PublicKey); !ok {
		return fmt.Errorf("not an RSA public key")
	}

	newToken, signedToken, err := app.ConfusionAttack(token, pubKeyData, claims, deleteClaims, claimsJSON, alg)
	if err != nil {
		return fmt.Errorf("generating token: %w", err)
	}

	ui.PrintRawToken(signedToken)
	ui.GenTokenTree(newToken)
	return nil
}
