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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

// match is the subset of yarad's /scan response we render. Kept local so this
// client shares no type (and thus no dependency) with the scanner package.
type match struct {
	Rule      string            `json:"rule"`
	Namespace string            `json:"namespace"`
	Meta      map[string]string `json:"meta"`
}

type scanResponse struct {
	Matches []match `json:"matches"`
}

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

	matches, err := postScan(*url, tok, *name, buf, *timeout)
	if err != nil {
		if *failOpen {
			fmt.Fprintf(os.Stderr, "strix-scan: scanner unreachable, failing open (clean): %v\n", err)
			return 0
		}
		fmt.Fprintln(os.Stderr, "strix-scan:", err)
		return 2
	}

	actionable := actionableMatches(matches)

	// -json / -label render a structured verdict from the actionable matches'
	// metadata. They print on a clean result too (so a labeller can record a
	// negative), and never honour -quiet (their output IS the point).
	if *jsonOut {
		v := verdictFor(actionable)
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(v)
		if !v.Malicious {
			return 0
		}
		return 1
	}
	if *labelOut {
		v := verdictFor(actionable)
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

// verdict is the structured -json output. Family is the single canonical malware
// family for the input ("" when no family-bearing rule matched); Rules lists the
// matched (actionable) rule names. Confidence is "family" when a family was
// resolved, "rule" when rules matched but none carried family metadata, and
// "" when nothing matched.
type verdict struct {
	Malicious  bool     `json:"malicious"`
	Family     string   `json:"family"`
	Confidence string   `json:"confidence"`
	Rules      []string `json:"rules"`
}

// familyMetaKeys are the rule-meta keys that carry a malware family, in priority
// order. A rule that sets one of these is "family-bearing"; a rule with none is a
// generic / technique rule (http, meth_get_eip, pe_*, SUSP_*, …) and never
// contributes a family label.
var familyMetaKeys = []string{"family", "malware_family", "actor"}

// verdictFor builds the structured verdict from the actionable matches. The
// reported Family is the first family-bearing match's family (one family per
// file = highest-confidence family-bearing hit); generic/technique rules that
// carry no family meta are dropped from family consideration but still count
// toward Malicious + Rules.
func verdictFor(matches []match) verdict {
	v := verdict{Rules: make([]string, 0, len(matches))}
	for _, m := range matches {
		v.Malicious = true
		v.Rules = append(v.Rules, m.Rule)
		if v.Family == "" {
			if fam := familyOf(m); fam != "" {
				v.Family = fam
			}
		}
	}
	switch {
	case v.Family != "":
		v.Confidence = "family"
	case v.Malicious:
		v.Confidence = "rule"
	}
	return v
}

// familyOf extracts a family string from one match's metadata, preferring the
// keys in familyMetaKeys. Returns "" for a generic/technique rule that carries no
// family meta (the caller drops it from family consideration).
func familyOf(m match) string {
	for _, k := range familyMetaKeys {
		if v := strings.TrimSpace(m.Meta[k]); v != "" {
			return v
		}
	}
	return ""
}

func actionableMatches(matches []match) []match {
	if len(matches) == 0 {
		return nil
	}
	var out []match
	for i, m := range matches {
		if m.Meta != nil && (m.Meta["mailstrix_canary"] == "1" || m.Meta["mailstrix_allow"] == "1") {
			if out == nil {
				out = make([]match, 0, len(matches)-1)
				out = append(out, matches[:i]...)
			}
			continue
		}
		if out != nil {
			out = append(out, m)
		}
	}
	if out == nil {
		return matches
	}
	return out
}

// postScan POSTs buf to <url>/scan and returns the matches. It mirrors the
// rspamd plugin's wire format: X-MAILSTRIX-Token for auth, base64 X-MAILSTRIX-Filename
// for the name. Redirects are NOT followed — a /scan endpoint never legitimately
// 3xx, and following one would copy the token header onto the redirect target
// (possibly another host), leaking the secret.
func postScan(base, token, name string, buf []byte, timeout time.Duration) ([]match, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	hc := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	endpoint := strings.TrimRight(base, "/") + "/scan"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Close = true // one-shot CLI: close the connection, don't pool a keep-alive
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "strix-scan/"+version)
	// Token is optional: omit the header when empty so this works against an open
	// (token-less) yarad too. When set, the server requires it.
	if token != "" {
		req.Header.Set("X-MAILSTRIX-Token", token)
	}
	if name != "" {
		req.Header.Set("X-MAILSTRIX-Filename", base64.StdEncoding.EncodeToString([]byte(name)))
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var out scanResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out.Matches, nil
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
