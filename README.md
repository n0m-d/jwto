# JWT0 (`jwt0`)

[![Release](https://github.com/n0m-d/jwto/actions/workflows/release.yml/badge.svg)](https://github.com/n0m-d/jwto/actions/workflows/release.yml)

A command-line tool for inspecting and tampering with JSON Web Tokens (JWTs). Built for authorized security testing, CTF challenges, and debugging JWT handling in applications you own or have permission to test.

---

## Features

- **Debug** — decode and pretty-print a token's header and payload
- **Bypass** — generate tokens with the `none` algorithm (signature bypass)
- **Confusion** — perform RSA → HMAC algorithm confusion attacks
- **Dict** — brute-force HMAC secrets (`HS256` / `HS384` / `HS512`) using a wordlist
- **Sign** — re-sign a token with a known secret after tampering claims
- **Verify** — check if an HMAC secret matches a JWT signature
- **Request** — send HTTP requests with custom headers (curl-like), optional proxy / no-follow redirects

---

## Requirements

- Go 1.21+

---

## Installation

Clone the repository and build the binary:

```bash
git clone https://github.com/n0m-d/jwto.git
cd jwto
go build -o jwto ./cmd/jwto

```

Or use Make:

```bash

make build

```

Or use `task`:

```bash

task build

```

Or run directly without installing:

```bash
go run ./cmd/jwto <command> [flags]
```

---

## Usage

```sh
      .                ...    .     ...          .....                          
  .x88888x.         .~'"888x.!**h.-''888h.    .H8888888h.  ~-.      .n~~%x.     
 :8**888888X.  :>  dX   '8888   :X   48888>   888888888888x  '>   x88X   888.   
 f    '888888x./  '888x  8888  X88.  '8888>  X~     '?888888hx~  X888X   8888L  
'       '*88888~  '88888 8888X:8888:   )?""' '      x8.^"*88*"  X8888X   88888  
 \.    .  '?)X.    '8888>8888 '88888>.88h.    '-:- X8888x       88888X   88888X 
  '~=-^   X88> ~     '8" 888f  '8888>X88888.       488888>      88888X   88888X 
         X8888  ~   -~' '8%"     88" '88888X     .. '"88*       88888X   88888f 
         488888     .H888n.      XHn.  '*88!   x88888nX"      . 48888X   88888  
 .xx.     88888X   :88888888x..x88888X.  '!   !"*8888888n..  :   ?888X   8888"  
'*8888.   '88888>  f  ^%∞88888% '*88888nx"   '    "*88888888*     "88X   88*'   
  88888    '8888>       '"**"'    '"**""             ^"***"'        ^"==="'     
  '8888>    '888                                                                
   "8888     8%                                                                 
    '"888x:-"          

                   - JWT0 - CLI Tool for JWT Tampering & Debugging -

usage: jwto [<flags>] <command> [<args> ...]

CLI Tool for JWT Tampering & Debugging


Flags:
  -h, --[no-]help          Show context-sensitive help (also try --help-long and --help-man).
  -j, --jwt=JWT            JWT to debug
  -c, --claims=CLAIMS ...  Payload claim key=value (infers bool/int/float/null; quote to force string)
      --claims-json=CLAIMS-JSON  
                           Payload claims as a JSON object (arrays/objects/typed values)
  -r, --delete_claims=DELETE_CLAIMS ...  
                           Delete Payload Claims

Commands:
help [<command>...]
    Show help.

bypass [<flags>]
    Bypass Signature Verification

debug
    Debug the provided token

confusion [<flags>]
    Algorithm Confusion Attack

dict [<flags>]
    Dictionary for Brute Force Attack

sign --secret=SECRET [<flags>]
    Sign the JWT with an HMAC secret

verify --secret=SECRET [<flags>]
    Verify HMAC secret against the JWT

request --url=URL [<flags>]
    Send an HTTP request (curl-like)

```

Most commands require a JWT via `--jwt` / `-j`. The `request` command does **not** need a JWT — pass tokens via headers instead.

### Global flags

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--jwt` | `-j` | Yes* | The JWT string to inspect or tamper with |
| `--claims` | `-c` | No | Add/overwrite claims as `key=value` (infers bool/int/float/null; quote to force string). Can be repeated |
| `--claims-json` | | No | Claims as a JSON object (arrays, nested objects, explicit types) |
| `--delete_claims` | `-r` | No | Remove payload claims by name. Can be repeated |
| `--help` | `-h` | No | Show help |

\* Not required for `request`.

Claim flags are available on `bypass`, `confusion`, and `sign`.

`--claims` type inference:

| Value | JSON type |
|-------|-----------|
| `true` / `false` | boolean |
| `null` | null |
| `1999999999` | number (int) |
| `3.14` | number (float) |
| `"true"` / `'123'` | string (quotes stripped) |
| anything else | string |

```bash
# Typed claims via -c
jwto -j "<TOKEN>" bypass -c admin=true -c exp=1999999999

# Force a string that looks like a bool/number
jwto -j "<TOKEN>" sign --secret "password" -c 'admin="true"'

# Arrays / nested objects
jwto -j "<TOKEN>" bypass --claims-json '{"admin":true,"roles":["user","admin"]}'
```

### Commands

#### `debug`

Decode the token and display its raw string, segments, header, and payload.

```bash
jwto -j "<TOKEN>" debug
```

#### `bypass`

Strip or replace the signature to test servers that accept unsigned tokens or the `none` algorithm.

| Flag | Default | Description |
|------|---------|-------------|
| `--alg` | `none` | Signing algorithm: `none`, `None`, `NONE`, or `default` (keeps original) |

```bash
jwto -j "<TOKEN>" bypass
jwto -j "<TOKEN>" bypass --alg=None
jwto -j "<TOKEN>" bypass -c admin=true -c role=admin -r exp
jwto -j "<TOKEN>" bypass --claims-json '{"admin":true,"nbf":null}'
```

Output is an unsigned token (`header.payload.`) with a trailing dot and no signature.

#### `confusion`

Re-sign an RSA JWT as HMAC using the RSA public key as the HMAC secret. Supports `HS256`, `HS384`, and `HS512`.

| Flag | Required | Description |
|------|----------|-------------|
| `--pub_key` | Yes | Path to the RSA public key file (PEM format) |
| `--alg` | No | HMAC algorithm: `HS256`, `HS384`, or `HS512` (default: `HS256`) |

```bash
jwto -j "<TOKEN>" confusion --pub_key ./wordlists/public.pem
jwto -j "<TOKEN>" confusion --pub_key ./public.pem --alg HS512
jwto -j "<TOKEN>" confusion --pub_key ./public.pem -c role=admin -r exp
```

#### `dict`

Brute-force the HMAC signing secret against a wordlist. Supports `HS256`, `HS384`, and `HS512` only.

| Flag | Default | Description |
|------|---------|-------------|
| `--file` | | Path to a wordlist (one candidate secret per line) |
| `--workers` | `5` | Parallel workers (capped at `GOMAXPROCS × 4`) |

```bash
jwto -j "<TOKEN>" dict --file ./wordlists/rockyou.txt --workers 10
```

Stops early when a match is found. Prints the secret and elapsed time on success.

#### `sign`

Tamper claims and re-sign with an HMAC secret. Supports `HS256`, `HS384`, and `HS512`. Verifies the secret against the original token before tampering (use `--no-verify` to skip).

| Flag | Required | Description |
|------|----------|-------------|
| `--secret` | Yes | HMAC signing secret |
| `--alg` | No | Signing algorithm: `HS256`, `HS384`, or `HS512` (defaults to token algorithm) |
| `--no-verify` | No | Skip secret verification before signing |

```bash
jwto -j "<TOKEN>" sign --secret "your-secret" -c role=admin
jwto -j "<TOKEN>" sign --secret "your-secret" --alg HS384 -r exp
jwto -j "<TOKEN>" sign --secret "your-secret" --no-verify -c role=admin
```

#### `verify`

Check whether an HMAC secret matches the JWT signature.

| Flag | Required | Description |
|------|----------|-------------|
| `--secret` | Yes | HMAC secret to test |
| `--alg` | No | Algorithm: `HS256`, `HS384`, or `HS512` (defaults to token algorithm) |

```bash
jwto -j "<TOKEN>" verify --secret "password"
jwto -j "<TOKEN>" verify --secret "password" --alg HS256
```

#### `request`

Send an HTTP request with custom headers. No `--jwt` flag needed — you control how credentials are sent (Bearer header, cookie, custom header, etc.).

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--url` | `-u` | Yes | Target URL |
| `--method` | `-X` | No | `GET` or `POST` (default: `GET`) |
| `--header` | `-H` | No | Request header as `Key=Value`. Can be repeated |
| `--header-file` | | No | File with `Name: value` per line. Can be repeated |
| `--body` | `-d` | No | Request body (POST) |
| `--proxy` | | No | Proxy URL (e.g. `http://127.0.0.1:8080`) |
| `--insecure` | `-k` | No | Skip TLS certificate verification (use with intercepting proxies) |
| `--disable-redirect` | | No | Do not follow HTTP redirects; return the 3xx response as-is |
| `--headers` | `-I` | No | Only print response headers (omit the body) |

```bash
# Bearer token
jwto request -u https://api.example.com/me \
  -H "Authorization=Bearer eyJhbGci..."

# Cookie-based session
jwto request -u https://api.example.com/admin \
  -H "Cookie=session=eyJhbGci..."

# POST with body
jwto request -u https://api.example.com/login -X POST \
  -H "Authorization=Bearer eyJhbGci..." \
  -d '{"user":"admin"}'

# Headers from file (flag headers override file values)
jwto request -u https://api.example.com/api \
  --header-file ./headers.txt \
  -H "X-Custom=yes"

# Through Burp/proxy (TLS skip is opt-in)
jwto request -u https://api.example.com/me \
  -H "Authorization=Bearer eyJhbGci..." \
  --proxy http://127.0.0.1:8080 \
  --insecure

# Do not follow redirect
jwto request -u https://api.example.com/login \
  -H "Authorization=Bearer eyJhbGci..." \
  --disable-redirect

# Response headers only
jwto request -u https://api.example.com/me \
  -H "Authorization=Bearer eyJhbGci..." \
  --headers
```

Header file format:

```
Authorization: Bearer eyJhbGci...
Cookie: session=eyJhbGci...
X-Api-Key: secret
```

---

## Examples

```bash
# Inspect a token
jwto -j "<TOKEN>" debug

# None-algorithm bypass with elevated role
jwto -j "<TOKEN>" bypass -c admin=true -c role=admin

# Algorithm confusion
jwto -j "<TOKEN>" confusion --pub_key ./wordlists/public.pem

# Crack a weak HMAC secret
jwto -j "<TOKEN>" dict --file ./wordlists/rockyou.txt

# Re-sign after tampering
jwto -j "<TOKEN>" sign --secret "password" -c admin=true

# Verify secret before signing
jwto -j "<TOKEN>" verify --secret "password"

# Send request without --jwt
jwto request -u https://api.example.com/me -H "Authorization=Bearer <TOKEN>"
```

---

## Help

```bash
jwto --help
jwto debug --help
jwto bypass --help
jwto confusion --help
jwto dict --help
jwto sign --help
jwto verify --help
jwto request --help
```

---

## Development

```bash
go test ./...
go build -o jwto ./cmd/jwto
```

---

## Disclaimer

> This tool is intended for security testing and educational purposes only. Use this tool only on systems you own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this program.

---

## Acknowledgment

- https://github.com/ticarpi/jwt_tool
