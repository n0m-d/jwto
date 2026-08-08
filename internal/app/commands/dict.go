package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/briandowns/spinner"
	"github.com/golang-jwt/jwt/v5"
	"github.com/n0m-d/jwto/internal/app"
	"github.com/n0m-d/jwto/internal/ui"
)

// HandleDictionary processes the dictionary attack command for Brute Force attacks.
func HandleDictionary(token *jwt.Token, filePath string, workers int) error {
	if filePath == "" {
		return fmt.Errorf("wordlist path is required")
	}

	alg := token.Method.Alg()
	if _, ok := app.HMACSigningMethods[alg]; !ok {
		return fmt.Errorf("unsupported algorithm: %s, supports only HMAC algorithms", alg)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("reading list: %w", err)
	}
	defer f.Close()

	start := time.Now()
	tokenString := token.Raw

	s := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
	s.Suffix = ui.AnsiYellow + " [*] Processing...\n" + ui.AnsiReset
	s.FinalMSG = ui.AnsiGreen + "[+] Process Completed!\n\n" + ui.AnsiReset
	s.Color("magenta")
	s.Start()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wordChan := make(chan string, workers)
	var wg sync.WaitGroup
	var found atomic.Bool
	var secretMu sync.Mutex
	var secret string

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordChan {
				if found.Load() {
					return
				}
				match, err := app.VerifyHMAC(tokenString, word, alg)
				if err != nil || !match {
					continue
				}
				if found.CompareAndSwap(false, true) {
					secretMu.Lock()
					secret = word
					secretMu.Unlock()
					cancel()
				}
				return
			}
		}()
	}

	sendWord := func(word string) bool {
		select {
		case <-ctx.Done():
			return false
		case wordChan <- word:
			return true
		}
	}

	const bufSize = 1 << 20 // 1 MB
	buf := make([]byte, bufSize)
	partial := []byte{}

readLoop:
	for {
		if ctx.Err() != nil {
			break
		}

		n, err := f.Read(buf)
		if n > 0 {
			chunk := append(partial, buf[:n]...)

			for {
				newline := bytes.IndexByte(chunk, '\n')
				if newline < 0 {
					break
				}

				word := string(bytes.TrimSpace(chunk[:newline]))
				chunk = chunk[newline+1:]

				if word != "" && !sendWord(word) {
					break readLoop
				}
			}

			partial = append(partial[:0], chunk...)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			close(wordChan)
			wg.Wait()
			s.Stop()
			return fmt.Errorf("reading wordlist: %w", err)
		}
	}

	if ctx.Err() == nil && len(partial) > 0 {
		if word := string(bytes.TrimSpace(partial)); word != "" {
			sendWord(word)
		}
	}

	close(wordChan)
	wg.Wait()
	s.Stop()

	end := time.Now()

	fmt.Println(ui.AnsiGreen + "[+] Time taken: " + end.Sub(start).String() + ui.AnsiReset)

	if secret == "" {
		fmt.Println(ui.AnsiRed + "[-] Secret not found" + ui.AnsiReset)
		return nil
	}
	fmt.Println(ui.AnsiGreen + "[+] Secret found: " + ui.AnsiYellow + secret + ui.AnsiReset)

	return nil
}
