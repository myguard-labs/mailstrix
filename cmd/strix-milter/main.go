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
// What is scanned: the milter protocol delivers the header block and the body
// separately, and this filter reassembles them into the complete RFC 5322 message
// before posting it — the same raw bytes strix-scan sends when it reads an .eml.
// Scanning the body alone would strip the MIME framing (Content-Type, boundary,
// Content-Transfer-Encoding, filename) that the extractor needs.
//
// Headers stamped on every message. Any sender-supplied X-Mailstrix-* header is
// DELETED first (the milter negotiates SMFIF_CHGHDRS for exactly this), so a
// hostile sender cannot forge a clean verdict that a downstream first-match
// header lookup would read instead of ours:
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
	"net/textproto"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

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

// maxHeaderValueLen caps ANY stamped header value, so no single value (notably
// X-Mailstrix-Info, which quotes a remote server's error) can push the header
// line past RFC 5322's 998-octet limit.
const maxHeaderValueLen = 400

// maxRuleHeaderLen is the budget joinRules may spend on rule names before it
// switches to a "(+N more)" tail. It MUST leave room for that tail inside
// maxHeaderValueLen, or sanitizeHeaderValue's clamp would cut the tail off and
// the header would silently look like a complete list when it is truncated.
const maxRuleHeaderLen = maxHeaderValueLen - 32

// scanFilename is the name reported to strixd for a milter-scanned message, so
// name/extension-keyed rules see a consistent, message-shaped name (we are
// posting a whole RFC 5322 message, exactly as strix-scan does for an .eml).
const scanFilename = "message.eml"

func main() { os.Exit(run(os.Args[1:])) }

type config struct {
	url      string
	listen   string
	token    string
	timeout  time.Duration
	maxBody  int64
	maxConns int
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
	maxConns := fs.Int("max-conns", 64, "max concurrent MTA connections; further connections wait. Bounds memory at roughly max-conns x max-body, so a flood of large messages cannot OOM the filter (which would restart it and, with milter_default_action=accept, let mail through unscanned)")
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
	if *maxConns <= 0 {
		*maxConns = 64
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

	cfg := config{url: *url, listen: *listen, token: tok, timeout: *timeout, maxBody: *maxBody, maxConns: *maxConns, logClean: *logClean}
	return serve(ln, cfg, log.New(os.Stderr, "strix-milter: ", log.LstdFlags))
}

// serve runs the milter server on ln until SIGINT/SIGTERM. It always returns 0
// on a clean shutdown: an MTA restarting us must not see a spurious failure.
// milterActions are the option bits we negotiate with the MTA. OptChangeHeader is
// load-bearing, not decorative: the MTA refuses any action that was not
// negotiated, so dropping it would make every forged-header delete in Body() a
// silent no-op — the guard would still be in the code and inert on the wire.
const milterActions = milter.OptAddHeader | milter.OptChangeHeader

// milterProtocol suppresses the callbacks we do not use. Headers, end-of-headers
// and body must all stay ENABLED: all three feed the message we reassemble.
const milterProtocol = milter.OptNoConnect | milter.OptNoHelo | milter.OptNoMailFrom | milter.OptNoRcptTo

func serve(ln net.Listener, cfg config, lg *log.Logger) int {
	client := verdict.NewClient(cfg.url, cfg.token, "strix-milter/"+version, cfg.timeout)

	// Bound concurrency at the ACCEPT, not per message. go-milter spawns a
	// goroutine per connection with no cap of its own, and each in-flight message
	// holds up to max-body in memory (twice, briefly, while it is being POSTed).
	// Unbounded, a spammer opening many concurrent sessions with large messages
	// could OOM us — and because the MTA is configured to fail open, the restart
	// window would deliver mail UNSCANNED. Capping accepts turns that into
	// backpressure on the MTA instead.
	ln = limitListener(ln, cfg.maxConns)

	srv := &milter.Server{
		NewMilter: func() milter.Milter {
			return &strixMilter{cfg: cfg, client: client, log: lg}
		},
		Actions:  milterActions,
		Protocol: milterProtocol,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	lg.Printf("listening on %s, scanning via %s (timeout %s, max-body %d, max-conns %d)",
		cfg.listen, cfg.url, cfg.timeout, cfg.maxBody, cfg.maxConns)

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

	// msg is the message being reassembled: the header block, then a blank line,
	// then the body — i.e. the same raw RFC 5322 bytes strix-scan posts when it
	// reads an .eml off disk. The milter protocol hands us headers and body
	// SEPARATELY, and scanning the body alone would strip exactly the framing the
	// extractor needs (Content-Type, boundary=, Content-Transfer-Encoding,
	// Content-Disposition filename=). strixd has no MIME parser of its own — it
	// carves a whole message — so a headerless body is a different, weaker input:
	// attachment carving would degrade to accidental base64-run detection and every
	// name/extension-keyed rule would go dead. Reassemble, don't shortcut.
	msg      []byte
	inBody   bool // the blank line has been written; msg is now accumulating body
	oversize bool // message exceeded max-body: do NOT scan a truncated prefix
	subject  string

	// forged counts inbound X-Mailstrix-* headers per canonical name, so Body()
	// can DELETE them (ChangeHeader with an empty value) before stamping our own.
	// Without this a sender could ship their own "X-Mailstrix-Status: clean" and
	// any downstream consumer doing a first-match header lookup — which is what
	// net/mail, textproto.MIMEHeader.Get and most MUA/Sieve implementations do —
	// would read the ATTACKER's verdict instead of ours.
	forged map[string]int

	// stamp writes one verdict header. It is a field, not a direct call to
	// Modifier.AddHeader, purely so the tests can observe what we stamp:
	// milter.Modifier is a struct with unexported fields and no interface, so a
	// test cannot construct a working one. Nil means "use the real Modifier"
	// (set in Body); the tests install their own recorder. NOTE: the seam takes
	// the RAW value — sanitising is the production path's job, so a test can
	// catch its removal.
	stamp func(name, value string)

	// strip deletes one inbound header occurrence (same seam rationale as stamp).
	strip func(index int, name string)
}

// Header buffers each header line into the message being reassembled, records the
// Subject for logging, and counts any inbound X-Mailstrix-* header so Body() can
// delete it before stamping ours.
func (s *strixMilter) Header(name, value string, m *milter.Modifier) (milter.Response, error) {
	if strings.EqualFold(name, "Subject") {
		s.subject = value
	}
	if strings.HasPrefix(strings.ToLower(name), strings.ToLower(headerPrefix)) {
		canon := textproto.CanonicalMIMEHeaderKey(name)
		if s.forged == nil {
			s.forged = make(map[string]int)
		}
		s.forged[canon]++
		s.log.Printf("WARNING: inbound message carries a forged %s: %q — deleting it before stamping (subject %q)",
			name, truncate(value, 120), truncate(s.subject, 80))
		// Deliberately NOT copied into s.msg: a forged verdict header must not be
		// part of what we hand the scanner either.
		return milter.RespContinue, nil
	}
	s.appendMsg([]byte(name + ": " + value + "\r\n"))
	return milter.RespContinue, nil
}

// Headers marks the end of the header block: write the blank line that separates
// headers from body, so what we post is a complete RFC 5322 message.
func (s *strixMilter) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	s.appendMsg([]byte("\r\n"))
	s.inBody = true
	return milter.RespContinue, nil
}

// BodyChunk accumulates the message body. The cap covers the WHOLE message
// (headers + body), matching strix-scan's -max-body over the whole .eml.
func (s *strixMilter) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	s.appendMsg(chunk)
	return milter.RespContinue, nil
}

// appendMsg accumulates message bytes up to max-body. Past the cap we stop
// buffering and latch oversize: posting only the first max-body bytes would turn
// a message whose dropper sits after the cap into a clean-looking scan — a silent
// miss. We would rather stamp "unknown" and let the MTA decide.
func (s *strixMilter) appendMsg(b []byte) {
	if s.oversize {
		return
	}
	if int64(len(s.msg))+int64(len(b)) > s.cfg.maxBody {
		s.oversize = true
		s.msg = nil // release the partial buffer; it is unusable
		return
	}
	s.msg = append(s.msg, b...)
}

// Body is the end of the message: scan, stamp, ACCEPT. Every path through this
// function returns RespAccept — including every error path. That is the contract.
func (s *strixMilter) Body(m *milter.Modifier) (milter.Response, error) {
	defer s.reset()

	sink := s.stamp
	if sink == nil {
		// Stamping is best-effort: if the MTA rejects a header add we still accept
		// the message (and say so), because failing to annotate is not a reason to
		// bounce mail.
		sink = func(name, value string) {
			if err := m.AddHeader(name, value); err != nil {
				s.log.Printf("add header %s: %v (message still accepted)", name, err)
			}
		}
	}
	// Sanitise HERE, above the sink, so it is on the single path both production
	// and the tests traverse. Doing it inside the default closure instead would
	// put it on a path a test seam REPLACES — the guard could then be deleted with
	// the injection tests still green (which is exactly what happened once).
	stamp := func(name, value string) { sink(name, sanitizeHeaderValue(value)) }
	strip := s.strip
	if strip == nil {
		strip = func(index int, name string) {
			// An empty value deletes the header (milter protocol convention).
			if err := m.ChangeHeader(index, name, ""); err != nil {
				s.log.Printf("delete forged header %s: %v (message still accepted)", name, err)
			}
		}
	}

	// Delete any sender-supplied X-Mailstrix-* header BEFORE stamping ours, so a
	// downstream first-match lookup cannot read a forged verdict. ChangeHeader's
	// index is per name and 1-based; delete from the highest index down so that
	// removing one does not renumber the ones we have not deleted yet.
	for name, n := range s.forged {
		for i := n; i >= 1; i-- {
			strip(i, name)
		}
	}

	st, rules, family, info := s.classify()

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
	if len(s.msg) == 0 {
		return statusUnknown, nil, "", "empty message"
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.timeout)
	defer cancel()

	// scanFilename gives the name/extension-keyed rules something consistent to
	// fire on, matching what strix-scan sends for a message read off disk.
	matches, err := s.client.Scan(ctx, scanFilename, s.msg)
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
	s.msg = nil
	s.inBody = false
	s.oversize = false
	s.subject = ""
	s.forged = nil
}

// sanitizeHeaderValue makes an arbitrary string safe as an RFC 5322 header value.
//
// Rule names come from rule files, but a family/meta string ultimately derives
// from data we do not control, and an error string can embed a remote server's
// response verbatim (see verdict.Client.Scan, which quotes the first 256 bytes of
// a non-200 body). So:
//
//   - CR, LF and NUL would let a value terminate our header and inject another;
//   - any other control byte, or any byte above US-ASCII, is illegal in a header
//     field body on a non-SMTPUTF8 transport (RFC 5322 §2.2) — emitting one could
//     make a downstream MTA reject the very message we promised to accept;
//   - an unbounded value could push the header line past the 998-octet limit.
//
// Everything outside printable ASCII therefore becomes '?', and the result is
// capped. This runs on the production stamping path, not in the test seam.
func sanitizeHeaderValue(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	if len(v) > maxHeaderValueLen {
		v = v[:maxHeaderValueLen] + "..."
	}
	return v
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

// truncate shortens a string for a LOG line (never a header). It cuts on a rune
// boundary: a Subject is attacker-controlled and routinely UTF-8, and slicing
// mid-codepoint would emit an invalid sequence into the log, which a strict
// journald/log-shipper consumer may mangle or drop.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
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
		// "address already in use" even though nobody is bound — so we clear it.
		// But ONLY if it is genuinely an orphaned socket:
		//
		//   - if something is listening, it belongs to a running instance and
		//     removing it would silently steal the socket out from under it (the
		//     MTA would keep talking to the now-unlinked inode);
		//   - if the path is not a socket at all, a typo in -listen (pointing at,
		//     say, an env file) must NOT cause us to delete an operator's file.
		if fi, err := os.Lstat(addr); err == nil {
			if fi.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("-listen: %s exists and is not a socket; refusing to remove it", addr)
			}
			if c, err := net.Dial("unix", addr); err == nil {
				_ = c.Close()
				return nil, fmt.Errorf("-listen: %s is already in use by a running process", addr)
			}
			if err := os.Remove(addr); err != nil {
				return nil, fmt.Errorf("-listen: removing stale socket %s: %w", addr, err)
			}
		}
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

// limitListener caps the number of simultaneously-accepted connections. It is
// golang.org/x/net/netutil.LimitListener in miniature — reproduced here rather
// than pulled in, to keep this binary's dependency surface at go-milter + stdlib.
//
// A connection over the cap is not refused; the accept simply waits for a slot,
// which the MTA sees as ordinary backpressure.
func limitListener(ln net.Listener, n int) net.Listener {
	return &limitedListener{Listener: ln, sem: make(chan struct{}, n)}
}

type limitedListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{} // take a slot (blocks at the cap)
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem // hand the slot back; nothing was accepted
		return nil, err
	}
	return &limitedConn{Conn: c, release: l.releaseOnce()}, nil
}

// releaseOnce returns a func that frees exactly one slot, however many times it
// is called. Close can legitimately be called more than once, and a double free
// would inflate the cap.
func (l *limitedListener) releaseOnce() func() {
	var once sync.Once
	return func() { once.Do(func() { <-l.sem }) }
}

type limitedConn struct {
	net.Conn
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}
