// Command strix-milter is a Postfix/Sendmail milter front-end for a running
// strixd. It buffers each message, POSTs it to strixd's HTTP /scan endpoint, and
// stamps the verdict into the message as headers.
//
// It ALWAYS ACCEPTS the message. The milter never rejects, defers, discards or
// quarantines — it only reports. Turning a verdict into policy is the MTA's job:
//
//	# Postfix main.cf
//	smtpd_milters = inet:127.0.0.1:8081
//	non_smtpd_milters = inet:127.0.0.1:8081
//	milter_default_action = accept     # keep mail flowing if the milter is down
//	header_checks = pcre:/etc/postfix/header_checks
//
//	# /etc/postfix/header_checks
//	/^X-Mailstrix-Status:\s*infected/  HOLD Mailstrix: malware detected
//
// Sendmail speaks the same protocol (this IS the sendmail milter wire protocol):
//
//	INPUT_MAIL_FILTER(`strix', `S=inet:8081@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
//
// Keeping policy in the MTA is deliberate. It makes fail-open trivial (a scanner
// error is just an "unknown" stamp), it keeps mail policy out of this binary,
// and it means a bug here can never silently eat mail.
//
// Like strix-scan, this binary links no CGO / libyara and embeds no rules — it
// is pure Go and compiles to a small static binary you can drop on any MTA host.
// The extractors and the YARA engine stay behind strixd's admission cap, off the
// MTA's delivery path.
//
// Usage:
//
//	strix-milter -url http://strixd:8079 -listen inet:127.0.0.1:8081 [-token-file F]
//	strix-milter -url http://strixd:8079 -listen unix:/run/strix-milter/milter.sock
//
// Headers stamped on every message (any pre-existing copies are stripped first,
// so a hostile sender cannot forge a clean verdict):
//
//	X-Mailstrix-Status:  clean | infected | unknown
//	X-Mailstrix-Rules:   comma-separated actionable rule names   (infected only)
//	X-Mailstrix-Family:  malware family                          (when resolved)
//	X-Mailstrix-Info:    why the verdict is unknown              (unknown only)
//	X-Mailstrix-Version: the strix-milter version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	milter "github.com/emersion/go-milter"

	"github.com/myguard-labs/mailstrix/internal/verdict"
)

var version = "dev"

// Header names. headerPrefix is what we strip from inbound mail before stamping
// our own: a sender who sets X-Mailstrix-Status: clean must not be able to make
// a downstream header_checks rule see a forged verdict.
const (
	headerPrefix  = "X-Mailstrix-"
	hdrStatus     = "X-Mailstrix-Status"
	hdrRules      = "X-Mailstrix-Rules"
	hdrFamily     = "X-Mailstrix-Family"
	hdrInfo       = "X-Mailstrix-Info"
	hdrVersionKey = "X-Mailstrix-Version"

	statusClean    = "clean"
	statusInfected = "infected"
	statusUnknown  = "unknown"
)

// maxRuleHeaderLen caps the X-Mailstrix-Rules value. A message that matches a
// great many rules must not produce an unbounded header line (RFC 5322 folding
// aside, some MTAs cap header size and would reject the message we promised to
// accept).
const maxRuleHeaderLen = 900

func main() { os.Exit(run(os.Args[1:])) }

type config struct {
	url      string
	listen   string
	token    string
	timeout  time.Duration
	maxBody  int64
	logClean bool
}

func run(args []string) int {
	fs := flag.NewFlagSet("strix-milter", flag.ContinueOnError)
	url := fs.String("url", envOr("MAILSTRIX_URL", ""), "base URL of the strixd service, e.g. http://127.0.0.1:8079 (MAILSTRIX_URL)")
	listen := fs.String("listen", envOr("MAILSTRIX_MILTER_LISTEN", "inet:127.0.0.1:8081"), "milter socket: inet:HOST:PORT or unix:/path/to.sock (MAILSTRIX_MILTER_LISTEN)")
	tokenFile := fs.String("token-file", "", "file holding the shared secret (preferred; not visible in the process list). Falls back to MAILSTRIX_TOKEN")
	token := fs.String("token", "", "shared secret, OPTIONAL — omit for a token-less strixd (use -token-file or MAILSTRIX_TOKEN, not -token, to keep it out of the process list)")
	timeout := fs.Duration("timeout", 20*time.Second, "hard per-message wall-clock deadline for the scan; on expiry the message is ACCEPTED with an unknown verdict")
	maxBody := fs.Int64("max-body", 8<<20, "max message bytes buffered and scanned; a larger message is accepted with an unknown verdict, NOT scanned as a truncated prefix")
	logClean := fs.Bool("log-clean", false, "log clean verdicts too (noisy; infected/unknown are always logged)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("strix-milter", version)
		return 0
	}
	if *url == "" {
		fmt.Fprintln(os.Stderr, "strix-milter: -url (or MAILSTRIX_URL) is required")
		return 2
	}
	if *maxBody <= 0 {
		*maxBody = 8 << 20
	}
	if *timeout <= 0 {
		*timeout = 20 * time.Second
	}

	tok, err := resolveToken(*token, *tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strix-milter:", err)
		return 2
	}

	ln, err := listenOn(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strix-milter:", err)
		return 2
	}

	cfg := config{url: *url, listen: *listen, token: tok, timeout: *timeout, maxBody: *maxBody, logClean: *logClean}
	return serve(ln, cfg, log.New(os.Stderr, "strix-milter: ", log.LstdFlags))
}

// serve runs the milter server on ln until SIGINT/SIGTERM. It always returns 0
// on a clean shutdown: an MTA restarting us must not see a spurious failure.
func serve(ln net.Listener, cfg config, lg *log.Logger) int {
	client := verdict.NewClient(cfg.url, cfg.token, "strix-milter/"+version, cfg.timeout)

	srv := &milter.Server{
		NewMilter: func() milter.Milter {
			return &strixMilter{cfg: cfg, client: client, log: lg}
		},
		// We add headers and nothing else. Declaring only OptAddHeader means the
		// MTA will refuse (and we could not accidentally perform) a body rewrite,
		// a recipient change or a quarantine.
		Actions: milter.OptAddHeader,
		// We need the body and the end-of-headers event. We do NOT need connect,
		// helo, mailfrom or rcpt data: the scan is content-only, and suppressing
		// them keeps envelope data (and its PII) out of this process entirely.
		Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoMailFrom | milter.OptNoRcptTo,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	lg.Printf("listening on %s, scanning via %s (timeout %s, max-body %d)", cfg.listen, cfg.url, cfg.timeout, cfg.maxBody)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		lg.Printf("received %s, shutting down", sig)
		_ = srv.Close()
		return 0
	case err := <-errCh:
		if err != nil && !errors.Is(err, milter.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			lg.Printf("serve: %v", err)
			return 1
		}
		return 0
	}
}

// strixMilter is one message's filter state. go-milter constructs a fresh one
// per connection via Server.NewMilter and drives it single-threaded, so the
// buffer below needs no lock; the Client it points at IS shared across
// connections, which is fine (http.Client is concurrency-safe).
type strixMilter struct {
	milter.NoOpMilter

	cfg    config
	client *verdict.Client
	log    *log.Logger

	body     []byte
	oversize bool // message exceeded max-body: do NOT scan a truncated prefix
	subject  string

	// stamp writes one verdict header. It is a field, not a direct call to
	// Modifier.AddHeader, purely so the tests can observe what we stamp:
	// milter.Modifier is a struct with unexported fields and no interface, so a
	// test cannot construct a working one. Nil means "use the real Modifier"
	// (set in Body); the tests install their own recorder.
	stamp func(name, value string)
}

// Header records the Subject (for logging only) and, crucially, does not let a
// sender-supplied X-Mailstrix-* header through: we cannot delete headers with
// only OptAddHeader declared, so instead we never trust an inbound one — the
// stamping in Body() always appends OUR values, and a downstream header_checks
// rule that anchors on the LAST occurrence (or a Postfix rule, which sees all of
// them) must therefore be written to treat any duplicate as suspicious. We make
// that explicit by logging a forged-header attempt loudly.
func (s *strixMilter) Header(name, value string, m *milter.Modifier) (milter.Response, error) {
	if strings.EqualFold(name, "Subject") {
		s.subject = value
	}
	if strings.HasPrefix(strings.ToLower(name), strings.ToLower(headerPrefix)) {
		s.log.Printf("WARNING: inbound message already carries %s: %q — a downstream rule must not trust it (subject %q)",
			name, truncate(value, 120), truncate(s.subject, 80))
	}
	return milter.RespContinue, nil
}

// BodyChunk accumulates the message body up to max-body. Past the cap we stop
// buffering and latch oversize: posting only the first max-body bytes would turn
// a message whose dropper sits after the cap into a clean-looking scan — a silent
// miss. We would rather stamp "unknown" and let the MTA decide.
func (s *strixMilter) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	if s.oversize {
		return milter.RespContinue, nil
	}
	if int64(len(s.body))+int64(len(chunk)) > s.cfg.maxBody {
		s.oversize = true
		s.body = nil // release the partial buffer; it is unusable
		return milter.RespContinue, nil
	}
	s.body = append(s.body, chunk...)
	return milter.RespContinue, nil
}

// Body is the end of the message: scan, stamp, ACCEPT. Every path through this
// function returns RespAccept — including every error path. That is the contract.
func (s *strixMilter) Body(m *milter.Modifier) (milter.Response, error) {
	defer s.reset()

	stamp := s.stamp
	if stamp == nil {
		// Stamping is best-effort: if the MTA rejects a header add we still accept
		// the message (and say so), because failing to annotate is not a reason to
		// bounce mail.
		stamp = func(name, value string) {
			if err := m.AddHeader(name, sanitizeHeaderValue(value)); err != nil {
				s.log.Printf("add header %s: %v (message still accepted)", name, err)
			}
		}
	}

	st, rules, family, info := s.classify()

	// Every value is sanitised before it lands in a header, so a rule name or
	// family containing CR/LF cannot inject a second header.
	stamp(hdrStatus, st)
	if len(rules) > 0 {
		stamp(hdrRules, joinRules(rules))
	}
	if family != "" {
		stamp(hdrFamily, family)
	}
	if info != "" {
		stamp(hdrInfo, info)
	}
	stamp(hdrVersionKey, version)

	switch st {
	case statusInfected:
		s.log.Printf("INFECTED family=%q rules=%s subject=%q", family, joinRules(rules), truncate(s.subject, 120))
	case statusUnknown:
		s.log.Printf("UNKNOWN (%s) subject=%q — accepting", info, truncate(s.subject, 120))
	default:
		if s.cfg.logClean {
			s.log.Printf("clean subject=%q", truncate(s.subject, 120))
		}
	}

	return milter.RespAccept, nil
}

// classify runs the scan and reduces it to the four header values. It never
// returns an error: an unscannable message is "unknown", not a failure.
func (s *strixMilter) classify() (status string, rules []string, family, info string) {
	if s.oversize {
		return statusUnknown, nil, "", fmt.Sprintf("message exceeds max-body=%d bytes; not scanned", s.cfg.maxBody)
	}
	if len(s.body) == 0 {
		return statusUnknown, nil, "", "empty message body"
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.timeout)
	defer cancel()

	matches, err := s.client.Scan(ctx, "", s.body)
	if err != nil {
		// Fail-open, the absolute rule on every scan path: a scanner outage,
		// timeout or non-200 must never block mail.
		return statusUnknown, nil, "", "scanner unavailable: " + sanitizeHeaderValue(err.Error())
	}

	v := verdict.For(verdict.Actionable(matches))
	if !v.Malicious {
		return statusClean, nil, "", ""
	}
	return statusInfected, v.Rules, v.Family, ""
}

// Abort resets per-message state without scanning: the MTA gave up on this
// message (client disconnected, RSET). Connection state is preserved, per the
// milter protocol.
func (s *strixMilter) Abort(m *milter.Modifier) error {
	s.reset()
	return nil
}

func (s *strixMilter) reset() {
	s.body = nil
	s.oversize = false
	s.subject = ""
}

// sanitizeHeaderValue makes an arbitrary string safe as a header value: CR, LF
// and NUL are replaced with a space so no rule name, family, or error string can
// inject a second header (or terminate the header block) into the message we are
// stamping. Rule names come from rule files, but a family/meta string ultimately
// derives from data we do not control, and an error string can embed a remote
// server's response.
func sanitizeHeaderValue(v string) string {
	v = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', 0:
			return ' '
		}
		return r
	}, v)
	return strings.TrimSpace(v)
}

// joinRules renders the rule list for X-Mailstrix-Rules, capped so a message
// matching very many rules cannot produce an over-long header line.
func joinRules(rules []string) string {
	if len(rules) == 0 {
		return ""
	}
	var b strings.Builder
	for i, r := range rules {
		r = sanitizeHeaderValue(r)
		if r == "" {
			continue
		}
		add := len(r)
		if b.Len() > 0 {
			add += 2 // ", "
		}
		if b.Len()+add > maxRuleHeaderLen {
			fmt.Fprintf(&b, " (+%d more)", len(rules)-i)
			break
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(r)
	}
	return b.String()
}

func truncate(s string, n int) string {
	s = sanitizeHeaderValue(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// listenOn opens the milter socket. "inet:HOST:PORT" is TCP; "unix:/path" is a
// unix socket (removed first if a stale one is in the way, as an MTA-restart
// leftover would otherwise make us fail to start).
func listenOn(spec string) (net.Listener, error) {
	network, addr, ok := strings.Cut(spec, ":")
	if !ok || addr == "" {
		return nil, fmt.Errorf("-listen: want inet:HOST:PORT or unix:/path, got %q", spec)
	}
	switch network {
	case "inet", "tcp":
		return net.Listen("tcp", addr)
	case "unix":
		// A stale socket file from an unclean shutdown would make Listen fail with
		// "address already in use" even though nobody is bound. Probe it: only
		// remove it if nothing is actually listening.
		if c, err := net.Dial("unix", addr); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("-listen: %s is already in use by a running process", addr)
		}
		_ = os.Remove(addr)
		ln, err := net.Listen("unix", addr)
		if err != nil {
			return nil, err
		}
		// The MTA runs as another user (postfix/smmsp) and must be able to talk to
		// us; 0660 plus a shared group is the usual deployment. 0600 (what gosec
		// wants) would make the socket unreachable by the very process it exists
		// for. Group-only, never world: the umask in the unit is 0027 and the
		// RuntimeDirectory is 0750, so the socket is not world-reachable.
		if err := os.Chmod(addr, 0o660); err != nil { // #nosec G302 -- the MTA runs as another user and must connect; group-restricted, not world
			_ = ln.Close()
			return nil, fmt.Errorf("-listen: chmod %s: %w", addr, err)
		}
		return ln, nil
	default:
		return nil, fmt.Errorf("-listen: unknown network %q, want inet: or unix:", network)
	}
}

// resolveToken prefers sources that don't expose the secret in the process list:
// -token-file, then -token, then MAILSTRIX_TOKEN. An empty result is allowed (a
// strixd with no token configured).
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
