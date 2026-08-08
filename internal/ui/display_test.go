package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/golang-jwt/jwt/v5"
)

func TestRenderTokenTreeFitsTerminal(t *testing.T) {
	raw := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	token, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	token.Raw = raw

	for _, width := range []int{40, 60, 80, 120} {
		out := renderTokenTree(token, width)
		for i, line := range strings.Split(out, "\n") {
			if w := lipgloss.Width(line); w > width {
				t.Fatalf("width %d line %d is %d cols:\n%s", width, i+1, w, line)
			}
		}
	}
}
