// Package cape implements opt-in CAPE transport and durable local job storage.
// Service activation, environment lookup and signal policy belong to callers.
package cape

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Revision pins the supported upstream CAPE API revision.
	Revision = "471ee4bb422ec4aa0f1aa1089540a1ad0b7d84f0"
	// MaxAttachment is the largest attachment accepted for submission.
	MaxAttachment = 10 << 20
	// MaxMetadata is the largest accepted task-metadata response.
	MaxMetadata = 64 << 10
	// MaxReport is the largest accepted report document.
	MaxReport = 8 << 20
	// MaxTaskIDs is the largest accepted task-ID set for one submission.
	MaxTaskIDs = 16
	// MaxDepth is the largest accepted JSON nesting depth.
	MaxDepth = 64
	// ConnectTimeout bounds connection establishment to the CAPE endpoint.
	ConnectTimeout = 5 * time.Second
	// RequestTimeout bounds one complete CAPE request.
	RequestTimeout = 30 * time.Second
)

// Code is safe to log. Errors deliberately do not wrap remote/provider errors.
type Code string

const (
	// Invalid indicates invalid local input or configuration.
	Invalid Code = "cape_invalid"
	// Closed indicates that the client no longer accepts work.
	Closed Code = "cape_closed"
	// Credential indicates local credential resolution failed.
	Credential Code = "cape_credential" // #nosec G101 -- protocol error code, not credential material
	// Unauthorized indicates that the endpoint rejected authentication.
	Unauthorized Code = "cape_unauthorized"
	// Throttled indicates that the endpoint requested bounded backoff.
	Throttled Code = "cape_throttled"
	// Transport indicates a network or TLS failure.
	Transport Code = "cape_transport"
	// Deadline indicates request cancellation or deadline expiry.
	Deadline Code = "cape_deadline"
	// Protocol indicates a malformed or incompatible endpoint response.
	Protocol Code = "cape_protocol"
	// TooLarge indicates that a configured protocol size limit was exceeded.
	TooLarge Code = "cape_too_large"
	// Remote indicates a sanitized endpoint-side failure.
	Remote Code = "cape_remote"
	// NotFound indicates that the requested remote task does not exist.
	NotFound Code = "cape_not_found"
)

// Error reports a sanitized CAPE client failure and optional retry hint.
type Error struct {
	Code Code
	// RetryAfter is a scheduler hint, clamped to [5s,5m] for throttles.
	// It never authorizes submission replay or extends a caller's deadline.
	RetryAfter time.Duration
}

// Error returns the safe-to-log failure code.
func (e *Error) Error() string { return string(e.Code) }

// CredentialProvider resolves only the configured service-account reference.
// Implementations must respect ctx and never log or wrap credential values.
type CredentialProvider interface {
	Token(ctx context.Context, reference string) (string, error)
}

// Config contains no token. AllowedDestination is the operator-approved numeric
// address and port; DNS is never consulted. Origin supplies the TLS hostname.
// A generation must change whenever endpoint, account or profile changes.
type Config struct {
	Origin              string
	AllowedDestination  netip.AddrPort
	Generation          string
	Machine             string
	CredentialReference string
	CAPEM               []byte
}

// TaskRef must come from the caller's durable owned-task record. Generation
// validation prevents cross-client mistakes; it does NOT establish ownership.
type TaskRef struct {
	ID         int64
	Generation string
}

// Submission always carries all confidently parsed, bounded IDs, even on error.
// UnknownDebt must remain durable when unobserved remote tasks may exist.
type Submission struct {
	Tasks       []TaskRef
	NoBytesSent bool
	UnknownDebt bool
}

// Client is a generation-bound CAPE API client with a pinned destination.
type Client struct {
	origin, generation, machine, credentialReference string
	credentials                                      CredentialProvider
	http                                             *http.Client
	transport                                        *http.Transport
	mu                                               sync.Mutex
	closed                                           bool
	next                                             uint64
	active                                           map[uint64]context.CancelFunc
}

// New validates a fixed private-service profile without contacting the endpoint.
// No ambient proxy, cookie jar, TLS override or arbitrary transport is accepted.
func New(cfg Config, credentials CredentialProvider) (*Client, error) {
	u, err := url.Parse(cfg.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		!cfg.AllowedDestination.IsValid() || cfg.AllowedDestination.Port() == 0 ||
		cfg.AllowedDestination.Addr().IsUnspecified() || cfg.AllowedDestination.Addr().IsMulticast() ||
		cfg.AllowedDestination.Addr().Zone() != "" || !identifier(cfg.Generation, 128) ||
		!identifier(cfg.Machine, 128) || strings.EqualFold(cfg.Machine, "all") ||
		!identifier(cfg.CredentialReference, 256) || credentials == nil {
		return nil, &Error{Code: Invalid}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if port != strconv.Itoa(int(cfg.AllowedDestination.Port())) {
		return nil, &Error{Code: Invalid}
	}
	var roots *x509.CertPool
	if len(cfg.CAPEM) != 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cfg.CAPEM) {
			return nil, &Error{Code: Invalid}
		}
	}
	destination := cfg.AllowedDestination.String()
	dialer := &net.Dialer{Timeout: ConnectTimeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, destination)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()},
		TLSHandshakeTimeout:    ConnectTimeout,
		ResponseHeaderTimeout:  RequestTimeout,
		MaxResponseHeaderBytes: MaxMetadata,
		DisableCompression:     true,
		// Fresh HTTP/1 connections avoid even net/http's transparent safe-read
		// retries. The scheduler owns every retry, including GET deletion.
		DisableKeepAlives: true,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	c := &Client{origin: u.String(), generation: cfg.Generation, machine: cfg.Machine,
		credentialReference: cfg.CredentialReference, credentials: credentials, transport: tr,
		active: make(map[uint64]context.CancelFunc)}
	c.http = &http.Client{Transport: tr, Timeout: RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}

func identifier(s string, maxLength int) bool {
	if len(s) == 0 || len(s) > maxLength {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func (c *Client) begin(parent context.Context) (context.Context, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, &Error{Code: Closed}
	}
	ctx, cancel := context.WithTimeout(parent, RequestTimeout)
	c.next++
	id := c.next
	c.active[id] = cancel
	return ctx, func() {
		cancel()
		c.mu.Lock()
		delete(c.active, id)
		c.mu.Unlock()
	}, nil
}

// Close rejects new work and cancels active requests; it is idempotent. Callers
// must still collect in-flight Submit results and durably retain cleanup debt.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	for _, cancel := range c.active {
		cancel()
	}
	c.mu.Unlock()
	c.transport.CloseIdleConnections()
	return nil
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	token, err := c.credentials.Token(ctx, c.credentialReference)
	if ctx.Err() != nil {
		return nil, &Error{Code: Deadline}
	}
	if err != nil || len(token) == 0 || len(token) > 4096 {
		return nil, &Error{Code: Credential}
	}
	for _, r := range token {
		if r < 0x21 || r > 0x7e {
			return nil, &Error{Code: Credential}
		}
	}
	if ctx.Err() != nil {
		return nil, &Error{Code: Deadline}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return nil, &Error{Code: Invalid}
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Pragma", "no-cache")
	return req, nil
}

// Submit takes ownership of source, whose Close MUST interrupt any blocked Read.
// It streams exactly size bytes, rejects short/long input, and closes source on
// every path. marker must be a persisted random 128-bit lowercase hex identifier.
// The source must be immutable (normally the caller's durable spool file).
// No POST is retried. NoBytesSent is true only before invoking the transport;
// all transport failures are conservatively uncertain, including TLS failures.
func (c *Client) Submit(parent context.Context, source io.ReadCloser, size int64, marker string) (Submission, error) {
	result := Submission{NoBytesSent: true}
	if source == nil {
		return result, &Error{Code: Invalid}
	}
	var closeOnce sync.Once
	closeSource := func() { closeOnce.Do(func() { _ = source.Close() }) }
	defer closeSource()
	if size < 1 || size > MaxAttachment || !hexID(marker) {
		return result, &Error{Code: Invalid}
	}
	ctx, done, err := c.begin(parent)
	if err != nil {
		return result, err
	}
	defer done()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return result, &Error{Code: Invalid}
	}
	reader, writer := io.Pipe()
	mw := multipart.NewWriter(writer)
	req, err := c.request(ctx, http.MethodPost, "/apiv2/tasks/create/file/", reader)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return result, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// No GetBody or idempotency headers: the transport cannot replay this body.
	stop := context.AfterFunc(ctx, func() { closeSource(); _ = reader.CloseWithError(context.Canceled) })
	defer stop()
	upload := make(chan error, 1)
	go func() {
		err := writeMultipart(mw, source, size, c.machine, marker, hex.EncodeToString(random[:])+".bin")
		_ = writer.CloseWithError(err)
		upload <- err
	}()
	result.NoBytesSent = false
	result.UnknownDebt = true
	body, responseErr := c.do(req, MaxMetadata)
	_ = reader.Close()
	closeSource()
	uploadErr := <-upload
	parsed, parseErr := parseSubmission(body, c.generation)
	result.Tasks = parsed
	if responseErr != nil {
		return result, responseErr
	}
	if uploadErr != nil {
		return result, &Error{Code: Invalid}
	}
	if parseErr != nil {
		return result, parseErr
	}
	result.UnknownDebt = false
	return result, nil
}

func writeMultipart(mw *multipart.Writer, source io.Reader, size int64, machine, marker, name string) error {
	if err := mw.WriteField("machine", machine); err != nil {
		return err
	}
	if err := mw.WriteField("custom", marker); err != nil {
		return err
	}
	part, err := mw.CreateFormFile("file", name)
	if err != nil {
		return err
	}
	if _, err = io.CopyN(part, source, size); err != nil {
		return err
	}
	// Read one byte past the declared size without transmitting it. Omit the
	// final multipart boundary on mismatch; remote acceptance is still uncertain.
	var extra [1]byte
	n, err := io.ReadFull(source, extra[:])
	if n != 0 || err != io.EOF {
		return &Error{Code: Invalid}
	}
	return mw.Close()
}

func hexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (c *Client) do(req *http.Request, limit int64) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return nil, &Error{Code: Deadline}
		}
		return nil, &Error{Code: Transport}
	}
	defer resp.Body.Close()
	statusErr := classifyHTTP(resp)
	encodingValid := validContentEncoding(resp.Header)
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(body)) > limit {
		body = body[:limit]
		if statusErr != nil {
			return body, statusErr
		}
		if !encodingValid {
			return body, &Error{Code: Protocol}
		}
		return body, &Error{Code: TooLarge}
	}
	if statusErr != nil {
		return body, statusErr
	}
	if !encodingValid {
		return body, &Error{Code: Protocol}
	}
	if readErr != nil {
		if req.Context().Err() != nil {
			return body, &Error{Code: Deadline}
		}
		return body, &Error{Code: Transport}
	}
	return body, nil
}

func validContentEncoding(header http.Header) bool {
	encodings := header.Values("Content-Encoding")
	return len(encodings) == 0 || len(encodings) == 1 && strings.EqualFold(encodings[0], "identity")
}

func classifyHTTP(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return &Error{Code: Unauthorized}
	case http.StatusTooManyRequests:
		return &Error{Code: Throttled, RetryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now())}
	case http.StatusNotFound:
		return &Error{Code: NotFound}
	default:
		if resp.StatusCode >= 500 {
			return &Error{Code: Remote}
		}
		return &Error{Code: Protocol}
	}
}

func retryAfter(s string, now time.Time) time.Duration {
	d := 5 * time.Second
	if len(s) <= 128 {
		if n, err := strconv.ParseUint(s, 10, 64); err == nil {
			if n > 300 {
				n = 300
			}
			d = time.Duration(n) * time.Second // #nosec G115 -- n is clamped to 300 above
		} else if date, err := http.ParseTime(s); err == nil {
			d = date.Sub(now)
		}
	}
	if d < 5*time.Second {
		return 5 * time.Second
	}
	if d > 5*time.Minute {
		return 5 * time.Minute
	}
	return d
}
