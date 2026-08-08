package commands

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/n0m-d/jwto/internal/app"
	"github.com/n0m-d/jwto/internal/ui"
)

// HandleVerify checks whether the provided secret matches the JWT signature.
func HandleVerify(token *jwt.Token, secret, alg string) error {
	ok, err := app.VerifyTokenSecret(token, secret, alg)
	if err != nil {
		return fmt.Errorf("verifying secret: %w", err)
	}

	if ok {
		fmt.Println(ui.AnsiGreen + "[+] Secret is valid for this token" + ui.AnsiReset)
		return nil
	}

	fmt.Println(ui.AnsiRed + "[-] Secret does not match token signature" + ui.AnsiReset)
	return fmt.Errorf("secret does not match token signature")
}
