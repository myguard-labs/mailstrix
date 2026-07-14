// Command strix-scan is a tiny, dependency-free client for a running yarad's
// HTTP /scan endpoint. It exists for the host that DELIVERS mail (a Dovecot LDA /
// Sieve box) but does NOT carry the YARA rules: pipe a message in, let the central
// yarad scan it, act on the exit code.
//
// Unlike the main `yarad` binary it links no CGO / libyara and embeds no rules —
// it is pure Go and compiles to a small static binary you can drop on any mail
// host. The whole job is: read the message (stdin or a file), POST it to
// <url>/scan with the shared token, and translate the JSON verdict into an exit
// code a Sieve `vnd.dovecot.execute` / pipe filter can branch on.
//
// Usage:
//
//	strix-scan -url http://strixd:8079 [-token-file F] [flags] [file]
//	strix-scan -url http://strixd:8079 - < /var/mail/cur/123:2,S
//	cat message | strix-scan -url http://strixd:8079
//
// Exit codes (scriptable):
//
//	0  clean — no actionable rule matched (also returned for log-only canary/
//	   allowlisted hits, and on a fail-open scanner outage)
//	1  at least one actionable rule matched
//	2  usage / read / (fail-closed) transport error
//
// Fail-open is the delivery-safety default: a scanner outage, timeout, or non-200
// is treated as clean (exit 0) so mail is never blocked by a down backend. Pass
// -fail-open=false for interactive triage, where a silent miss is worse than a
// visible error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/myguard-labs/mailstrix/internal/verdict"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("strix-scan", flag.ContinueOnError)
	url := fs.String("url", envOr("MAILSTRIX_URL", ""), "base URL of the strixd service, e.g. http://127.0.0.1:8079 (MAILSTRIX_URL)")
	tokenFile := fs.String("token-file", "", "file holding the shared secret (preferred; not visible in the process list). Falls back to MAILSTRIX_TOKEN")
	token := fs.String("token", "", "shared secret, OPTIONAL — omit for a token-less strixd (use -token-file or MAILSTRIX_TOKEN, not -token, to keep it out of the process list)")
	name := fs.String("filename", "", "attachment/message name sent as X-MAILSTRIX-Filename so name/extension-keyed rules fire")
	timeout := fs.Duration("timeout", 10*time.Second, "HTTP request timeout")
	maxBody := fs.Int64("max-body", 8<<20, "max bytes read from the input")
	failOpen := fs.Bool("fail-open", true, "on a transport/HTTP error treat the message as CLEAN (exit 0) so a scanner outage never blocks delivery; =false surfaces the error (exit 2)")
	quiet := fs.Bool("quiet", false, "print nothing on a match (rely on the exit code only)")
	jsonOut := fs.Bool("json", false, "emit a structured verdict {malicious,family,confidence,rules:[...]} as JSON instead of MATCH lines")
	labelOut := fs.Bool("label", false, "print a single `LABEL <family>` line for the highest-confidence family-bearing match (nothing if no family is known); for malware-store family labelling")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("strix-scan", version)
		return 0
	}
	if *url == "" {
		fmt.Fprintln(os.Stderr, "strix-scan: -url (or MAILSTRIX_URL) is required")
		return 2
	}
	if *jsonOut && *labelOut {
		fmt.Fprintln(os.Stderr, "strix-scan: -json and -label are mutually exclusive")
		return 2
	}
	if *maxBody <= 0 {
		*maxBody = 8 << 20
	}

	tok, err := resolveToken(*token, *tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strix-scan:", err)
		return 2
	}

	// Input: a single file argument, or stdin (no arg, or "-").
	var in io.Reader = os.Stdin
	if rest := fs.Args(); len(rest) > 1 {
		fmt.Fprintln(os.Stderr, "strix-scan: at most one input (a file or stdin)")
		return 2
	} else if len(rest) == 1 && rest[0] != "-" {
		f, err := os.Open(rest[0]) // #nosec G304 -- operator-supplied message path
		if err != nil {
			fmt.Fprintln(os.Stderr, "strix-scan:", err)
			return 2
		}
		defer f.Close()
		in = f
	}

	// Read one byte past the cap so an oversized input is DETECTED rather than
	// silently truncated. Posting only the first max-body bytes would turn a
	// message whose dropper sits after the cap into a clean-looking scan — a silent
	// miss. The server already rejects oversized requests before reading; the client
	// must not paper over that with a truncated prefix.
	buf, err := io.ReadAll(io.LimitReader(in, *maxBody+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "strix-scan: read:", err)
		return 2
	}
	if int64(len(buf)) > *maxBody {
		// Fail-open (delivery default): never block mail on an over-cap message, but
		// say so loudly so it is visible — DO NOT post the truncated prefix.
		if *failOpen {
			fmt.Fprintf(os.Stderr, "strix-scan: input exceeds -max-body=%d bytes, failing open (clean) without scanning a truncated prefix\n", *maxBody)
			return 0
		}
		// Fail-closed (interactive triage): a silent miss is worse than a visible error.
		fmt.Fprintf(os.Stderr, "strix-scan: input exceeds -max-body=%d bytes; refusing to scan a truncated prefix\n", *maxBody)
		return 2
	}

	hc := verdict.NewClient(*url, tok, "strix-scan/"+version, *timeout)
	defer hc.CloseIdle()
	matches, err := hc.Scan(context.Background(), *name, buf)
	if err != nil {
		if *failOpen {
			fmt.Fprintf(os.Stderr, "strix-scan: scanner unreachable, failing open (clean): %v\n", err)
			return 0
		}
		fmt.Fprintln(os.Stderr, "strix-scan:", err)
		return 2
	}

	actionable := verdict.Actionable(matches)

	// -json / -label render a structured verdict from the actionable matches'
	// metadata. They print on a clean result too (so a labeller can record a
	// negative), and never honour -quiet (their output IS the point).
	if *jsonOut {
		v := verdict.For(actionable)
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(v)
		if !v.Malicious {
			return 0
		}
		return 1
	}
	if *labelOut {
		v := verdict.For(actionable)
		if v.Family != "" {
			fmt.Println("LABEL", v.Family)
		}
		if !v.Malicious {
			return 0
		}
		return 1
	}

	if len(actionable) == 0 {
		return 0
	}
	if !*quiet {
		for _, m := range actionable {
			if m.Namespace != "" {
				fmt.Printf("MATCH %s (%s)\n", m.Rule, m.Namespace)
			} else {
				fmt.Printf("MATCH %s\n", m.Rule)
			}
		}
	}
	return 1
}

// resolveToken prefers sources that don't expose the secret in the process list:
// -token-file, then -token, then MAILSTRIX_TOKEN. An empty result is allowed (a
// server with no token configured).
func resolveToken(tokenFlag, tokenFile string) (string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile) // #nosec G304 -- operator-supplied token path
		if err != nil {
			return "", fmt.Errorf("-token-file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if tokenFlag != "" {
		return tokenFlag, nil
	}
	return strings.TrimSpace(os.Getenv("MAILSTRIX_TOKEN")), nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
