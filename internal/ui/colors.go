package ui

// Lipgloss palette — hex and ANSI-256 values for styled terminal UI.
const (
	ColorCyan    = "#00F0FF"
	ColorMagenta = "#B000F0"
	ColorLime    = "#39FF14"
	ColorPurple  = "#7D56F4"
	ColorAmber   = "#FFB000"

	ColorBlack = "0"
	ColorDim   = "241"
	ColorMuted = "245"
)

// ANSI palette — true-color escape sequences for plain terminal output.
const (
	AnsiReset         = "\033[0m"
	AnsiGreen         = "\033[38;2;128;255;128m"
	AnsiYellow        = "\033[38;2;253;227;124m"
	AnsiRed           = "\033[38;2;255;107;99m"
	AnsiBlue          = "\x1b[38;5;38m"
	AnsiBrightMagenta = "\033[38;2;255;0;255m"
)
