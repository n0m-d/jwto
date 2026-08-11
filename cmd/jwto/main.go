package main

import (
	"fmt"
	"os"

	_ "embed"

	"github.com/alecthomas/kingpin/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/n0m-d/jwto/internal/app/commands"
	"github.com/n0m-d/jwto/internal/ui"
)

//go:embed data/common_wordlist.txt.gz
var commonWordlistGz []byte

var (
	version = ""

	cliApp       = kingpin.New("jwto", "CLI Tool for JWT Tampering & Debugging")
	jwtString    = cliApp.Flag("jwt", "JWT to debug").Short('j').String()
	claims       = cliApp.Flag("claims", "Payload claim key=value (infers bool/int/float/null; quote to force string)").Short('c').StringMap()
	claimsJSON   = cliApp.Flag("claims-json", "Payload claims as a JSON object (arrays/objects/typed values)").String()
	deleteClaims = cliApp.Flag("delete_claims", "Delete Payload Claims").Short('r').Strings()

	bypass = cliApp.Command("bypass", "Bypass Signature Verification")
	alg    = bypass.Flag("alg", "Use none algorithm [none,None,NONE or default]").Default("none").String()

	debug = cliApp.Command("debug", "Debug the provided token")

	confusion    = cliApp.Command("confusion", "Algorithm Confusion Attack")
	pubKey       = confusion.Flag("pub_key", "Path to Public Key").String()
	confusionAlg = confusion.Flag("alg", "HMAC algorithm for confusion (HS256, HS384, HS512). Default: HS256").Default("HS256").String()

	dictionary = cliApp.Command("dict", "Dictionary for Brute Force Attack")
	file       = dictionary.Flag("file", "Path to wordlist (defaults to embedded common wordlist)").String()
	workers    = dictionary.Flag("workers", fmt.Sprintf("Number of workers (1-%d)", commands.MaxWorkers())).Default("5").Int()

	signing    = cliApp.Command("sign", "Sign the JWT with an HMAC secret")
	secret     = signing.Flag("secret", "HMAC signing secret").Required().String()
	signingAlg = signing.Flag("alg", "Signing algorithm (HS256, HS384, HS512). Defaults to token algorithm").Default("").String()
	noVerify   = signing.Flag("no-verify", "Skip secret verification before signing").Bool()

	verifyCmd    = cliApp.Command("verify", "Verify HMAC secret against the JWT")
	verifySecret = verifyCmd.Flag("secret", "HMAC secret to verify").Required().String()
	verifyAlg    = verifyCmd.Flag("alg", "Algorithm to verify against (HS256, HS384, HS512). Defaults to token algorithm").Default("").String()

	requestCmd      = cliApp.Command("request", "Send an HTTP request (curl-like)")
	targetURL       = requestCmd.Flag("url", "Target URL").Required().Short('u').String()
	method          = requestCmd.Flag("method", "HTTP method").Short('X').Default("GET").Enum("GET", "POST", "get", "post")
	reqHeaders      = requestCmd.Flag("header", "Request header (Key=Value). Can be repeated").Short('H').StringMap()
	headerFile      = requestCmd.Flag("header-file", "Path to file with headers (Name: value per line). Can be repeated").Strings()
	body            = requestCmd.Flag("body", "Request body for POST requests").Short('d').String()
	proxy           = requestCmd.Flag("proxy", "Proxy URL (e.g., http://127.0.0.1:8080)").String()
	insecure        = requestCmd.Flag("insecure", "Skip TLS certificate verification (useful with intercepting proxies)").Short('k').Bool()
	disableRedirect = requestCmd.Flag("disable-redirect", "Do not follow HTTP redirects (return the 3xx response)").Bool()
	headersOnly     = requestCmd.Flag("headers", "Only print the headers and not the body").Short('I').Bool()
)

func init() {
	cliApp.Version(version)
	printBanner()
	cliApp.HelpFlag.Short('h')
}

func main() {
	command := kingpin.MustParse(cliApp.Parse(os.Args[1:]))

	switch command {
	case requestCmd.FullCommand():
		if err := commands.HandleRequest(commands.RequestOptions{
			URL:             *targetURL,
			Method:          *method,
			Headers:         *reqHeaders,
			HeaderFiles:     *headerFile,
			Body:            *body,
			Proxy:           *proxy,
			Insecure:        *insecure,
			DisableRedirect: *disableRedirect,
			HeadersOnly:     *headersOnly,
		}); err != nil {
			fmt.Printf("Request Error: %v\n", err)
			os.Exit(1)
		}

	default:
		token, err := parseToken(*jwtString)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		switch command {
		case bypass.FullCommand():
			if err := commands.HandleBypass(token, *alg, *claims, *deleteClaims, *claimsJSON); err != nil {
				fmt.Printf("Bypass Error: %v\n", err)
				os.Exit(1)
			}

		case debug.FullCommand():
			ui.PrintRawToken(token.Raw)
			ui.GenTokenTree(token)

		case confusion.FullCommand():
			if err := commands.HandleConfusion(token, *pubKey, *claims, *deleteClaims, *claimsJSON, *confusionAlg); err != nil {
				fmt.Printf("Confusion Attack Error: %v\n", err)
				os.Exit(1)
			}

		case dictionary.FullCommand():
			w, capped, err := commands.ResolveWorkers(*workers)
			if err != nil {
				fmt.Printf("Dictionary Attack Error: %v\n", err)
				os.Exit(1)
			}
			if capped {
				fmt.Printf("[*] workers capped: %d -> %d (max for this system)\n", *workers, w)
			}
			if err := commands.HandleDictionary(token, *file, w, commonWordlistGz); err != nil {
				fmt.Printf("Dictionary Attack Error: %v\n", err)
				os.Exit(1)
			}

		case signing.FullCommand():
			if err := commands.HandleSigning(token, *secret, *signingAlg, *claims, *deleteClaims, *claimsJSON, *noVerify); err != nil {
				fmt.Printf("Signing Error: %v\n", err)
				os.Exit(1)
			}

		case verifyCmd.FullCommand():
			if err := commands.HandleVerify(token, *verifySecret, *verifyAlg); err != nil {
				fmt.Printf("Verify Error: %v\n", err)
				os.Exit(1)
			}

		default:
			fmt.Println("Please specify a valid subcommand: bypass, debug, confusion, dict, sign, verify, or request")
			os.Exit(1)
		}
	}
}

func printBanner() {
	banner := `
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
	
	           - JWT0 - CLI Tool for JWT Tampering & Debugging - ` + version + `
	`

	fmt.Println(ui.AnsiBlue + banner + ui.AnsiReset)
}

func parseToken(raw string) (*jwt.Token, error) {
	if raw == "" {
		return nil, fmt.Errorf("--jwt is required")
	}

	token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	return token, nil
}
