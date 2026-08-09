package commands

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/n0m-d/jwto/internal/ui"
)

// RequestOptions configures an outbound HTTP request.
type RequestOptions struct {
	URL             string
	Method          string
	Headers         map[string]string
	HeaderFiles     []string
	Body            string
	Proxy           string
	Insecure        bool
	DisableRedirect bool
	HeadersOnly     bool
}

// HandleRequest sends an HTTP request with the provided options.
func HandleRequest(opts RequestOptions) error {
	if opts.URL == "" {
		return fmt.Errorf("--url is required")
	}

	method := strings.ToUpper(strings.TrimSpace(opts.Method))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodPost:
	default:
		return fmt.Errorf("unsupported method %q: use GET or POST", method)
	}

	headers, err := mergeHeaders(opts.Headers, opts.HeaderFiles)
	if err != nil {
		return err
	}

	var body io.Reader
	if opts.Body != "" {
		body = strings.NewReader(opts.Body)
	}

	fmt.Println(ui.AnsiGreen + "[+] Sending request to " + ui.AnsiYellow + opts.URL + "... " + ui.AnsiReset)

	req, err := http.NewRequest(method, opts.URL, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if opts.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client, err := newHTTPClient(opts)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	printRequest(req)
	if opts.DisableRedirect && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		fmt.Println(ui.AnsiYellow + "[*] Redirect not followed (--disable-redirect)" + ui.AnsiReset)
	}
	printResponse(resp, respBody, opts.HeadersOnly)

	return nil
}

func newHTTPClient(opts RequestOptions) (*http.Client, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	if opts.Proxy != "" || opts.Insecure {
		transport := &http.Transport{}
		if opts.Proxy != "" {
			proxyURL, err := url.Parse(opts.Proxy)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy URL: %w", err)
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		if opts.Insecure {
			// Intentional: needed for intercepting proxies (e.g. Burp) with custom CAs.
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		}
		client.Transport = transport
	}

	if opts.DisableRedirect {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client, nil
}

func mergeHeaders(flags map[string]string, files []string) (map[string]string, error) {
	headers := make(map[string]string)

	for _, path := range files {
		fileHeaders, err := parseHeaderFile(path)
		if err != nil {
			return nil, err
		}
		for key, value := range fileHeaders {
			headers[key] = value
		}
	}

	for key, value := range flags {
		headers[key] = value
	}

	return headers, nil
}

func parseHeaderFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading header file %q: %w", path, err)
	}

	headers := make(map[string]string)
	for lineNum, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header at %s:%d: %q", path, lineNum+1, line)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("empty header name at %s:%d", path, lineNum+1)
		}
		headers[key] = value
	}

	return headers, nil
}

func printRequest(req *http.Request) {
	fmt.Printf("%s> %s %s%s\n", ui.AnsiYellow, req.Method, req.URL.String(), ui.AnsiReset)

	for key, values := range req.Header {
		for _, value := range values {
			fmt.Printf("%s> %s: %s%s\n", ui.AnsiBrightMagenta, key, value, ui.AnsiReset)
		}
	}
	fmt.Println()
}

func printResponse(resp *http.Response, body []byte, headersOnly bool) {
	statusColor := ui.AnsiGreen
	if resp.StatusCode >= 400 {
		statusColor = ui.AnsiRed
	}

	fmt.Printf("%s< %s %s%s\n", statusColor, resp.Proto, resp.Status, ui.AnsiReset)

	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("%s< %s: %s%s\n", statusColor, key, value, ui.AnsiReset)
		}
	}

	fmt.Println()
	if len(body) > 0 && !headersOnly {
		fmt.Println(string(bytes.TrimRight(body, "\n")))
	}
}
