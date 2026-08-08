package commands

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleRequestGETWithHeaders(t *testing.T) {
	var auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	token := "test.jwt.token"
	err := HandleRequest(RequestOptions{
		URL:     server.URL,
		Method:  "GET",
		Headers: map[string]string{"Authorization": "Bearer " + token},
	})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if auth != "Bearer "+token {
		t.Fatalf("Authorization = %q, want %q", auth, "Bearer "+token)
	}
}

func TestHandleRequestPOSTWithHeaders(t *testing.T) {
	var method, contentType, custom string
	var body []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		contentType = r.Header.Get("Content-Type")
		custom = r.Header.Get("X-Test")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	err := HandleRequest(RequestOptions{
		URL:     server.URL,
		Method:  "POST",
		Headers: map[string]string{"X-Test": "yes"},
		Body:    `{"name":"jwto"}`,
	})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if method != http.MethodPost {
		t.Fatalf("method = %q", method)
	}
	if contentType != "application/json" {
		t.Fatalf("content-type = %q", contentType)
	}
	if custom != "yes" {
		t.Fatalf("x-test = %q", custom)
	}
	if string(body) != `{"name":"jwto"}` {
		t.Fatalf("body = %q", string(body))
	}
}

func TestParseHeaderFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "headers.txt")
	content := "# comment\nAccept: application/json\nX-Api-Key: secret\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	headers, err := parseHeaderFile(path)
	if err != nil {
		t.Fatalf("parseHeaderFile() error = %v", err)
	}
	if headers["Accept"] != "application/json" {
		t.Fatalf("Accept = %q", headers["Accept"])
	}
	if headers["X-Api-Key"] != "secret" {
		t.Fatalf("X-Api-Key = %q", headers["X-Api-Key"])
	}
}

func TestHandleRequestDisableRedirect(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("followed"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	err := HandleRequest(RequestOptions{
		URL:             server.URL + "/start",
		Method:          "GET",
		DisableRedirect: true,
	})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (redirect must not be followed)", hits)
	}
}

func TestMergeHeadersFileAndFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "headers.txt")
	if err := os.WriteFile(path, []byte("X-Test: file\nAccept: text/plain\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	headers, err := mergeHeaders(map[string]string{"X-Test": "flag"}, []string{path})
	if err != nil {
		t.Fatalf("mergeHeaders() error = %v", err)
	}
	if headers["X-Test"] != "flag" {
		t.Fatalf("flag override failed: %q", headers["X-Test"])
	}
	if headers["Accept"] != "text/plain" {
		t.Fatalf("Accept = %q", headers["Accept"])
	}
}
