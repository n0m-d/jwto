package ui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/term"
)

const (
	defaultTermW   = 80
	minTermW       = 40
	rawTokenIndent = "    "
	truncateTail   = "…"
)

var (
	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(ColorPurple)).
			Padding(1, 2).
			Margin(1, 0)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(ColorCyan))

	sectionTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color(ColorMagenta))

	dimTextStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorDim))

	mutedTextStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorMuted))

	chipStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(ColorBlack)).
			Background(lipgloss.Color(ColorLime)).
			Padding(0, 1)

	chipAltStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(ColorBlack)).
			Background(lipgloss.Color(ColorMagenta)).
			Padding(0, 1)

	chipWarnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(ColorBlack)).
			Background(lipgloss.Color(ColorAmber)).
			Padding(0, 1)

	fieldStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorLime)).
			Bold(true)

	timestampStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorAmber)).
			Italic(true)

	segmentLabelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color(ColorCyan)).
				Bold(true)
)

func GenTokenTree(token *jwt.Token) {
	fmt.Println(renderTokenTree(token, terminalWidth()))
}

func renderTokenTree(token *jwt.Token, termW int) string {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "Error: unable to parse claims as MapClaims"
	}

	payload := make(map[string]interface{}, len(claims))
	for k, v := range claims {
		payload[k] = v
	}

	if termW < minTermW {
		termW = minTermW
	}

	panelW := termW - panelStyle.GetHorizontalBorderSize()
	textW := termW - panelStyle.GetHorizontalFrameSize()
	if textW < 20 {
		textW = 20
	}

	var sections []string
	sections = append(sections, renderKVSection("Header", mapRows(token.Header), textW, false))
	sections = append(sections, renderKVSection("Payload", mapRows(payload), textW, false))
	if token.Raw != "" {
		sections = append(sections, renderKVSection("Segments", [][]string{
			{"header", partAt(token.Raw, 0)},
			{"payload", partAt(token.Raw, 1)},
			{"signature", partAt(token.Raw, 2)},
		}, textW, true))
	}

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		titleStyle.Render("Decoded Token"),
		renderSummary(token),
		"",
		joinSections(sections, textW),
		"",
		renderFooter(token, payload),
	)

	return panelStyle.Width(panelW).Render(content)
}

func PrintRawToken(token string) {
	prefix := AnsiGreen + "[+] " + AnsiReset
	available := terminalWidth() - lipgloss.Width("[+] ")
	if available < 16 {
		available = 16
	}

	wrapped := wrapHard(token, available)
	fmt.Println(prefix + strings.ReplaceAll(wrapped, "\n", "\n"+rawTokenIndent))
}

func renderSummary(token *jwt.Token) string {
	alg := fmt.Sprintf("%v", token.Header["alg"])
	typ := fmt.Sprintf("%v", token.Header["typ"])
	if typ == "<nil>" {
		typ = "—"
	}

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		chipStyle.Render("alg"),
		" ",
		mutedTextStyle.Render(alg),
		"   ",
		chipAltStyle.Render("typ"),
		" ",
		mutedTextStyle.Render(typ),
		"   ",
		chipWarnStyle.Render("sig"),
		" ",
		mutedTextStyle.Render(signatureState(token.Raw)),
	)
}

func renderKVSection(title string, rows [][]string, width int, truncateAlways bool) string {
	keyW := 0
	for _, row := range rows {
		if w := lipgloss.Width(row[0]); w > keyW {
			keyW = w
		}
	}
	if keyW < 4 {
		keyW = 4
	}

	valueW := width - keyW - 4
	if valueW < 8 {
		valueW = 8
	}

	labelStyle := fieldStyle
	if truncateAlways {
		labelStyle = segmentLabelStyle
	}

	var lines []string
	lines = append(lines, sectionTitleStyle.Render(title))
	for _, row := range rows {
		key := row[0]
		val := row[1]
		if truncateAlways || lipgloss.Width(val) > valueW {
			val = truncate(val, valueW)
		}

		valStyle := mutedTextStyle
		if !truncateAlways && isTimestampClaim(key) {
			valStyle = timestampStyle
		}

		lines = append(lines, "  "+labelStyle.Render(padRight(key, keyW))+"  "+valStyle.Render(val))
	}

	return strings.Join(lines, "\n")
}

func joinSections(sections []string, width int) string {
	sep := dimTextStyle.Render(strings.Repeat("─", width))

	var out []string
	for i, section := range sections {
		out = append(out, section)
		if i < len(sections)-1 {
			out = append(out, sep)
		}
	}
	return strings.Join(out, "\n")
}

func renderFooter(token *jwt.Token, payload map[string]interface{}) string {
	return dimTextStyle.Render(fmt.Sprintf(
		"%d header fields  ·  %d payload fields",
		len(token.Header),
		len(payload),
	))
}

func signatureState(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) < 3 || parts[2] == "" {
		return "none"
	}
	return "present"
}

func isTimestampClaim(field string) bool {
	switch strings.ToLower(field) {
	case "iat", "exp", "nbf":
		return true
	default:
		return false
	}
}

func partAt(raw string, index int) string {
	parts := strings.Split(raw, ".")
	if index >= len(parts) {
		return ""
	}
	return parts[index]
}

func mapRows(data map[string]interface{}) [][]string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rows := make([][]string, len(keys))
	for i, k := range keys {
		rows[i] = []string{k, formatClaimValue(k, data[k])}
	}
	return rows
}

func toInt64(value any) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, true
	case float64:
		return int64(v), true
	}
	return 0, false
}

func formatClaimValue(key string, value any) string {
	if isTimestampClaim(key) {
		if unix, ok := toInt64(value); ok {
			return fmt.Sprintf("%d (unix) %s", unix, time.Unix(unix, 0).Format(time.RFC3339))
		}
	}

	if v, ok := value.(float64); ok && v == float64(int64(v)) {
		value = int64(v)
	}
	return fmt.Sprintf("%v", value)
}

func terminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return defaultTermW
	}
	return w
}

func padRight(s string, width int) string {
	pad := width - lipgloss.Width(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if width <= utf8.RuneCountInString(truncateTail) {
		return string([]rune(truncateTail)[:width])
	}

	budget := width - lipgloss.Width(truncateTail)
	var b strings.Builder
	n := 0
	for _, r := range s {
		rw := lipgloss.Width(string(r))
		if n+rw > budget {
			break
		}
		b.WriteRune(r)
		n += rw
	}
	return b.String() + truncateTail
}

func wrapHard(s string, width int) string {
	if width <= 0 || s == "" {
		return s
	}

	runes := []rune(s)
	if len(runes) <= width {
		return s
	}

	var b strings.Builder
	for i := 0; i < len(runes); i += width {
		if i > 0 {
			b.WriteByte('\n')
		}
		end := i + width
		if end > len(runes) {
			end = len(runes)
		}
		b.WriteString(string(runes[i:end]))
	}
	return b.String()
}
