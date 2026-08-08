package app

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// TamperClaims modifies JWT claims by adding custom claims and deleting specified ones.
// Optional claimsJSON is merged first (JSON object). String values from --claims are then
// type-inferred (bool/int/float/null, else string) and override JSON keys on conflict.
func TamperClaims(token *jwt.Token, customClaims map[string]string, deleteClaims []string, claimsJSON string) (jwt.MapClaims, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format: expected jwt.MapClaims")
	}

	if err := mergeClaimsJSON(claims, claimsJSON); err != nil {
		return nil, err
	}

	for k, v := range customClaims {
		claims[k] = ParseClaimValue(v)
	}

	for _, claim := range deleteClaims {
		delete(claims, claim)
	}

	return claims, nil
}

// ParseClaimValue converts a CLI claim string into a JSON-friendly Go value.
func ParseClaimValue(raw string) interface{} {
	s := strings.TrimSpace(raw)

	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}

	switch s {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}

	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}

	return s
}

func mergeClaimsJSON(claims jwt.MapClaims, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var extra map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &extra); err != nil {
		return fmt.Errorf("parsing --claims-json: %w", err)
	}
	if extra == nil {
		return fmt.Errorf("parsing --claims-json: expected a JSON object")
	}

	for k, v := range extra {
		claims[k] = v
	}
	return nil
}

// GenerateUnsignedToken generates an unsigned JWT with modified claims.
func GenerateUnsignedToken(originalToken *jwt.Token, signingMethod jwt.SigningMethod, modifiedClaims map[string]interface{}) (*jwt.Token, string, error) {
	newToken := jwt.NewWithClaims(signingMethod, jwt.MapClaims(modifiedClaims))

	unsignedToken, err := newToken.SigningString()
	if err != nil {
		return nil, "", fmt.Errorf("generating signing string: %w", err)
	}

	signed := unsignedToken + "."
	newToken.Raw = signed
	return newToken, signed, nil
}
