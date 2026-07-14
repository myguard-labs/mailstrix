package verdict

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout is used when a Client is given a non-positive timeout.
const DefaultTimeout = 10 * time.Second

// maxResponseBody caps the /scan response we will decode. A compromised or
// confused endpoint must not be able to make a client allocate without bound.
const maxResponseBody = 4 << 20

// Client POSTs messages to a strixd /scan endpoint. The zero value is not
// usable — build one with NewClient.
//
// Both CGO-free clients (strix-scan, strix-milter) use this so the wire format,
// the token handling and the redirect refusal below cannot drift apart.
type Client struct {
	base      string
	token     string
	userAgent string
	hc        *http.Client
	timeout   time.Duration
}

// NewClient returns a Client for the strixd at base (e.g. http://127.0.0.1:8079).
// token may be empty, for a token-less strixd. userAgent identifies the caller
// (e.g. "strix-milter/1.2.0").
//
// Redirects are NOT followed: a /scan endpoint never legitimately 3xx, and
// following one would copy the token header onto the redirect target (possibly
// another host), leaking the shared secret.
func NewClient(base, token, userAgent string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		base:      base,
		token:     token,
		userAgent: userAgent,
		timeout:   timeout,
		hc: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Scan POSTs buf to <base>/scan and returns the matches strixd reported (all of
// them — the caller decides what is Actionable). name, when non-empty, is sent
// as X-MAILSTRIX-Filename so name/extension-keyed rules fire.
//
// The supplied ctx bounds the call in addition to the client's own timeout,
// whichever fires first.
func (c *Client) Scan(ctx context.Context, name string, buf []byte) ([]Match, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	endpoint := strings.TrimRight(c.base, "/") + "/scan"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	// Token is optional: omit the header when empty so this works against an open
	// (token-less) strixd too. When set, the server requires it.
	if c.token != "" {
		req.Header.Set("X-MAILSTRIX-Token", c.token)
	}
	if name != "" {
		req.Header.Set("X-MAILSTRIX-Filename", base64.StdEncoding.EncodeToString([]byte(name)))
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var out Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out.Matches, nil
}

// CloseIdle closes any pooled keep-alive connections. One-shot CLI callers use
// this; the long-lived milter deliberately does not (it wants the pool).
func (c *Client) CloseIdle() { c.hc.CloseIdleConnections() }
