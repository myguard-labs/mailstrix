package cape

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const marker = "00112233445566778899aabbccddeeff"
const success = `{"error":[],"errors":[],"data":{"task_ids":[41],"message":"Task ID 41 has been submitted"}}`

type credentialFunc func(context.Context, string) (string, error)

func (f credentialFunc) Token(ctx context.Context, reference string) (string, error) {
	return f(ctx, reference)
}

func fixture(t *testing.T, handler http.HandlerFunc) (*Client, Config) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	addr, err := netip.ParseAddrPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Origin: s.URL, AllowedDestination: addr, Generation: "fixture-v1", Machine: "one-vm",
		CredentialReference: "fixture-account", CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})}
	c, err := New(cfg, credentialFunc(func(_ context.Context, reference string) (string, error) {
		if reference != "fixture-account" {
			return "", errors.New("unexpected reference")
		}
		return "synthetic-test-token", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, cfg
}

func owned() TaskRef                { return TaskRef{ID: 41, Generation: "fixture-v1"} }
func source(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
func assertCode(t *testing.T, err error, code Code) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error code = %v, want %s", err, code)
	}
}

func TestSubmitExactBytes(t *testing.T) {
	for _, size := range []int{1, MaxAttachment} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xA5}, size)
			var calls atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "POST" || r.URL.Path != "/apiv2/tasks/create/file/" {
					t.Error("wrong submission route")
				}
				if r.Header.Get("Authorization") != "Token synthetic-test-token" || r.Header.Get("Cookie") != "" {
					t.Error("wrong authentication")
				}
				mr, err := r.MultipartReader()
				if err != nil {
					t.Error(err)
					return
				}
				fields := map[string]string{}
				for {
					part, err := mr.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Error(err)
						return
					}
					data, err := io.ReadAll(part)
					if err != nil {
						t.Error(err)
						return
					}
					if _, exists := fields[part.FormName()]; exists {
						t.Error("duplicate multipart field")
					}
					if part.FormName() == "file" {
						name := part.FileName()
						if len(name) != 36 || !hexID(strings.TrimSuffix(name, ".bin")) {
							t.Error("filename is not generated")
						}
						if !bytes.Equal(payload, data) {
							t.Error("submitted bytes differ")
						}
						fields["file"] = "seen"
					} else {
						fields[part.FormName()] = string(data)
					}
				}
				if len(fields) != 3 || fields["file"] != "seen" || fields["machine"] != "one-vm" || fields["custom"] != marker {
					t.Error("multipart profile differs")
				}
				_, _ = io.WriteString(w, success)
			})
			result, err := c.Submit(context.Background(), io.NopCloser(bytes.NewReader(payload)), int64(size), marker)
			if err != nil || len(result.Tasks) != 1 || result.Tasks[0] != owned() || result.NoBytesSent || result.UnknownDebt {
				t.Fatalf("submission result invalid: %+v %v", result, err)
			}
			if calls.Load() != 1 {
				t.Fatal("POST count is not one")
			}
		})
	}
}

func TestSubmitInputLimits(t *testing.T) {
	var calls atomic.Int32
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, success)
	})
	for _, size := range []int64{-1, 0, MaxAttachment + 1} {
		result, err := c.Submit(context.Background(), source("x"), size, marker)
		assertCode(t, err, Invalid)
		if !result.NoBytesSent || result.UnknownDebt {
			t.Fatal("invalid input was sent")
		}
	}
	result, err := c.Submit(context.Background(), source("x"), 1, "user-filename.exe")
	assertCode(t, err, Invalid)
	if !result.NoBytesSent || calls.Load() != 0 {
		t.Fatal("invalid marker reached transport")
	}
	for _, input := range []string{"x", "xxx"} {
		result, err := c.Submit(context.Background(), source(input), 2, marker)
		if err == nil || result.NoBytesSent || !result.UnknownDebt {
			t.Fatal("size mismatch accepted or marked safe to replay")
		}
	}
}

func TestSubmitUncertainIDs(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		ids        int
	}{
		{"multiple", `{"error":[],"errors":[],"data":{"task_ids":[41,42]}}`, 2},
		{"partial-error", `{"error":[],"errors":[{"fixture":"failed"}],"data":{"task_ids":[41]}}`, 1},
		{"error-true", `{"error":true,"data":{"task_ids":[41]}}`, 1},
		{"truncated", `{"data":{"task_ids":[41,42,`, 2},
		{"invalid-middle", `{"error":[],"errors":[],"data":{"task_ids":[41,"bad",42,0,-1,2147483648,43]}}`, 3},
		{"duplicate-id", `{"error":[],"errors":[],"data":{"task_ids":[41,41]}}`, 1},
		{"duplicate-key", `{"error":[],"errors":[],"data":{"task_ids":[41],"task_ids":[42]}}`, 2},
		{"unrelated", `{"message":"task_ids: [41]","x":{"data":{"task_ids":[42]}}}`, 0},
		{"dotted-key", `{"data.task_ids":[41]}`, 0},
		{"missing-errors", `{"error":[],"data":{"task_ids":[41]}}`, 1},
		{"string-id", `{"error":[],"errors":[],"data":{"task_ids":["41"]}}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = io.WriteString(w, tc.body)
			})
			result, err := c.Submit(context.Background(), source("x"), 1, marker)
			assertCode(t, err, Protocol)
			if len(result.Tasks) != tc.ids || !result.UnknownDebt || result.NoBytesSent {
				t.Fatalf("lost cleanup identities/uncertainty: %+v", result)
			}
			if calls.Load() != 1 {
				t.Fatal("ambiguous POST was repeated")
			}
		})
	}
}

func TestTaskIDCap(t *testing.T) {
	for _, count := range []int{16, 17, 30} {
		parts := make([]string, count)
		for i := range parts {
			parts[i] = fmt.Sprint(i + 1)
		}
		tasks, err := parseSubmission([]byte(`{"error":[],"errors":[],"data":{"task_ids":[`+strings.Join(parts, ",")+`]}}`), "fixture-v1")
		assertCode(t, err, Protocol)
		if len(tasks) != 16 || tasks[0].ID != 1 || tasks[15].ID != 16 {
			t.Fatal("bounded task IDs lost or cap exceeded")
		}
	}
}

func TestNoRedirectOrPOSTRetry(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Location", "/unexpected")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, success)
			})
			result, err := c.Submit(context.Background(), source("x"), 1, marker)
			if err == nil || !result.UnknownDebt || len(result.Tasks) != 1 {
				t.Fatal("non-success response accepted or IDs lost")
			}
			if calls.Load() != 1 {
				t.Fatal("redirect followed or POST repeated")
			}
		})
	}
}

func TestReadRedirect(t *testing.T) {
	var calls atomic.Int32
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/unexpected" {
			w.Header().Set("Location", "/unexpected")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, `{"error":false,"data":"reported"}`)
	})
	_, err := c.Status(context.Background(), owned())
	assertCode(t, err, Protocol)
	if calls.Load() != 1 {
		t.Fatal("redirect was followed")
	}
}

func TestMetadataCapPreservesIDs(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"data":{"task_ids":[41]},"padding":"`+strings.Repeat("x", MaxMetadata)+`"}`)
	})
	result, err := c.Submit(context.Background(), source("x"), 1, marker)
	assertCode(t, err, TooLarge)
	if len(result.Tasks) != 1 || !result.UnknownDebt {
		t.Fatal("oversized response lost known ID or unknown debt")
	}
}

func TestNewValidationAndTLS(t *testing.T) {
	var calls atomic.Int32
	_, cfg := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"error":false,"data":"reported"}`)
	})
	provider := credentialFunc(func(context.Context, string) (string, error) { return "fixture-token", nil })
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Origin = strings.Replace(c.Origin, "https:", "http:", 1) },
		func(c *Config) { c.Origin += "/" }, func(c *Config) { c.Origin += "?x=1" }, func(c *Config) { c.Origin += "#x" },
		func(c *Config) { c.Origin = strings.Replace(c.Origin, "https://", "https://user:pass@", 1) },
		func(c *Config) { c.AllowedDestination = netip.MustParseAddrPort("127.0.0.1:1") },
		func(c *Config) { c.Machine = "ALL" }, func(c *Config) { c.Machine = "a,b" }, func(c *Config) { c.Machine = "" },
		func(c *Config) { c.CredentialReference = "" }, func(c *Config) { c.CAPEM = []byte("bad") },
	} {
		bad := cfg
		mutate(&bad)
		c, err := New(bad, provider)
		if c != nil {
			_ = c.Close()
		}
		assertCode(t, err, Invalid)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.CAPEM = nil }, func(c *Config) { c.Origin = "https://wrong.invalid:" + fmt.Sprint(c.AllowedDestination.Port()) }} {
		bad := cfg
		mutate(&bad)
		c, err := New(bad, provider)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Status(context.Background(), owned())
		_ = c.Close()
		assertCode(t, err, Transport)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid/unverified destination received request")
	}
}

func TestTLSHandshakeTimeoutBounds(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	addr := netip.MustParseAddrPort(listener.Addr().String())
	c, err := New(Config{Origin: "https://localhost:" + fmt.Sprint(addr.Port()), AllowedDestination: addr,
		Generation: "fixture-v1", Machine: "one-vm", CredentialReference: "fixture-account"},
		credentialFunc(func(context.Context, string) (string, error) { return "synthetic-test-token", nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	c.transport.TLSHandshakeTimeout = 50 * time.Millisecond
	started := time.Now()
	_, err = c.Status(context.Background(), owned())
	elapsed := time.Since(started)
	assertCode(t, err, Transport)
	if elapsed < 35*time.Millisecond || elapsed > 750*time.Millisecond {
		t.Fatalf("TLS handshake timeout elapsed=%v outside [35ms,750ms]", elapsed)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("TLS timeout test never reached accepted connection")
	}
}

func TestCredentialsAndLifecycle(t *testing.T) {
	var calls atomic.Int32
	c, cfg := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"error":false,"data":"pending"}`)
	})
	for _, tc := range []struct {
		name, value string
		providerErr error
	}{
		{"provider-error", "synthetic-valid-token", errors.New("secret-fixture")},
		{"empty", "", nil},
		{"length4097", strings.Repeat("x", 4097), nil},
		{"invalid-char", "synthetic token", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := New(cfg, credentialFunc(func(context.Context, string) (string, error) { return tc.value, tc.providerErr }))
			if err != nil {
				t.Fatal(err)
			}
			result, err := bad.Submit(context.Background(), source("x"), 1, marker)
			_ = bad.Close()
			assertCode(t, err, Credential)
			if strings.Contains(err.Error(), "secret") || !result.NoBytesSent {
				t.Fatal("credential leaked or failure sent bytes")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := c.Submit(ctx, source("x"), 1, marker)
	assertCode(t, err, Deadline)
	if !result.NoBytesSent {
		t.Fatal("pre-cancelled request was attempted")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_, err = c.Status(context.Background(), owned())
	assertCode(t, err, Closed)
	if calls.Load() != 0 {
		t.Fatal("failed/closed client performed request")
	}
}

func TestCredentialMaximumLength(t *testing.T) {
	token := strings.Repeat("x", 4096)
	var calls atomic.Int32
	c, cfg := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Token "+token {
			t.Error("maximum-length token changed")
		}
		_, _ = io.WriteString(w, `{"error":false,"data":"pending"}`)
	})
	_ = c.Close()
	accepted, err := New(cfg, credentialFunc(func(context.Context, string) (string, error) { return token, nil }))
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	status, err := accepted.Status(context.Background(), owned())
	if err != nil || status != "pending" || calls.Load() != 1 {
		t.Fatalf("4096-byte token rejected: status=%q calls=%d err=%v", status, calls.Load(), err)
	}
}

func TestCredentialProviderDeadline(t *testing.T) {
	var calls atomic.Int32
	c, cfg := fixture(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	_ = c.Close()
	cooperative, err := New(cfg, credentialFunc(func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer cooperative.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := cooperative.Submit(ctx, source("x"), 1, marker)
	assertCode(t, err, Deadline)
	if !result.NoBytesSent || result.UnknownDebt || calls.Load() != 0 {
		t.Fatalf("provider timeout attempted submission: %+v calls=%d", result, calls.Load())
	}
}

func TestResponseBodyDeadline(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   Code
	}{
		{"submit", http.StatusOK, Deadline},
		{"status", http.StatusOK, Deadline},
		{"unauthorized", http.StatusUnauthorized, Unauthorized},
		{"throttled", http.StatusTooManyRequests, Throttled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"data":{"task_ids":[41,42,`)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if tc.name == "status" {
				_, err := c.Status(ctx, owned())
				assertCode(t, err, tc.code)
			} else {
				result, err := c.Submit(ctx, source("x"), 1, marker)
				assertCode(t, err, tc.code)
				if len(result.Tasks) != 2 || result.Tasks[0] != owned() || result.Tasks[1] != (TaskRef{ID: 42, Generation: "fixture-v1"}) || !result.UnknownDebt || result.NoBytesSent {
					t.Fatalf("body timeout lost cleanup identities/uncertainty: %+v", result)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("request count = %d, want 1", calls.Load())
			}
		})
	}
}

type countedSource struct {
	reader io.Reader
	closed chan struct{}
	closes atomic.Int32
}

func (s *countedSource) Read(p []byte) (int, error) {
	if s.reader != nil {
		return s.reader.Read(p)
	}
	<-s.closed
	return 0, io.ErrClosedPipe
}

func (s *countedSource) Close() error {
	if s.closes.Add(1) != 1 {
		return errors.New("source closed twice")
	}
	close(s.closed)
	return nil
}

func TestSubmitClosesSourceExactlyOnce(t *testing.T) {
	for _, name := range []string{"success", "failed", "canceled"} {
		t.Run(name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if name == "failed" {
					w.WriteHeader(http.StatusInternalServerError)
				}
				_, _ = io.WriteString(w, success)
			})
			s := &countedSource{reader: strings.NewReader("x"), closed: make(chan struct{})}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if name == "canceled" {
				s.reader = nil
			}
			_, err := c.Submit(ctx, s, 1, marker)
			switch name {
			case "success":
				if err != nil {
					t.Fatal(err)
				}
			case "failed":
				assertCode(t, err, Remote)
			case "canceled":
				assertCode(t, err, Deadline)
			}
			if got := s.closes.Load(); got != 1 {
				t.Fatalf("source Close calls = %d, want exactly 1", got)
			}
		})
	}
}

func TestStatusAndDelete(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
			t.Error("read/delete request not fixed uncached GET")
		}
		switch r.URL.Path {
		case "/apiv2/tasks/status/41/":
			_, _ = io.WriteString(w, `{"error":false,"data":"completed"}`)
		case "/apiv2/tasks/delete/41/":
			_, _ = io.WriteString(w, `{"data":"Task(s) ID(s) 41 has been deleted"}`)
		default:
			t.Error("wrong path")
		}
	})
	status, err := c.Status(context.Background(), owned())
	if err != nil || status != "completed" {
		t.Fatal("completed status failed")
	}
	state, err := c.Delete(context.Background(), owned())
	if err != nil || state != DeleteAcknowledgedUnverified {
		t.Fatal("deletion ACK is not unverified")
	}
	for _, task := range []TaskRef{{ID: 0, Generation: "fixture-v1"}, {ID: -1, Generation: "fixture-v1"}, {ID: 1 << 31, Generation: "fixture-v1"}, {ID: 41, Generation: "different"}} {
		_, err = c.Delete(context.Background(), task)
		assertCode(t, err, Invalid)
	}
}

func TestReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       Code
		status     int
		encoding   string
	}{
		{"unauthorized", `secret-fixture`, Unauthorized, 401, ""}, {"forbidden", `secret-fixture`, Unauthorized, 403, ""},
		{"throttled", `secret-fixture`, Throttled, 429, ""}, {"missing", `{}`, NotFound, 404, ""},
		{"unknown", `{"error":false,"data":"new-state"}`, Protocol, 200, ""},
		{"error", `{"error":true,"data":"reported"}`, Protocol, 200, ""},
		{"malformed", `{`, Protocol, 200, ""}, {"trailing", `{"error":false,"data":"reported"}{}`, Protocol, 200, ""},
		{"compressed", `{"error":false,"data":"reported"}`, Protocol, 200, "gzip"},
		{"duplicate", `{"error":true,"error":false,"data":"reported"}`, Protocol, 200, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.Header().Set("Retry-After", "999999")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := c.Status(context.Background(), owned())
			assertCode(t, err, tc.code)
			if strings.Contains(err.Error(), "secret-fixture") || calls.Load() != 1 {
				t.Fatal("body leak or automatic retry")
			}
			if tc.code == Throttled && err.(*Error).RetryAfter != 5*time.Minute {
				t.Fatal("Retry-After not bounded")
			}
		})
	}
}

func TestResponseContentEncoding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		valid  bool
	}{
		{name: "absent", valid: true},
		{name: "identity", values: []string{"identity"}, valid: true},
		{name: "repeated-identity", values: []string{"identity", "identity"}},
		{name: "combined-identity", values: []string{"identity, identity"}},
		{name: "empty", values: []string{""}},
		{name: "leading-whitespace", values: []string{" identity"}},
		{name: "trailing-whitespace", values: []string{"identity "}},
		{name: "noncanonical-case", values: []string{"Identity"}},
		{name: "other", values: []string{"gzip"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			for _, value := range tc.values {
				header.Add("Content-Encoding", value)
			}
			if got := validContentEncoding(header); got != tc.valid {
				t.Fatalf("validContentEncoding() = %t, want %t", got, tc.valid)
			}
		})
	}
}

func TestResponseContentEncodingStatusPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   Code
	}{
		{name: "success-status", status: http.StatusOK, code: Protocol},
		{name: "error-status", status: http.StatusInternalServerError, code: Remote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Encoding", "identity")
				w.Header().Add("Content-Encoding", "identity")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, "remote response")
			})
			_, err := c.Status(context.Background(), owned())
			assertCode(t, err, tc.code)
		})
	}
}

func TestSubmitInvalidContentEncodingPreservesBoundedTaskID(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Add("Content-Encoding", "identity")
		w.Header().Add("Content-Encoding", "identity")
		_, _ = io.WriteString(w, `{"data":{"task_ids":[41]},"padding":"`+strings.Repeat("x", MaxMetadata)+`"}`)
	})
	result, err := c.Submit(context.Background(), source("x"), 1, marker)
	assertCode(t, err, Protocol)
	if len(result.Tasks) != 1 || result.Tasks[0].ID != 41 || !result.UnknownDebt || result.NoBytesSent {
		t.Fatalf("invalid encoding lost bounded cleanup identity or uncertainty: %+v", result)
	}
}

func TestDeleteDoesNotConfirmMissingOrOrphaned(t *testing.T) {
	for _, body := range []string{`{"error":true,"orphaned":"fixture"}`, `{"error":true,"failed":"fixture"}`, `{}`, `{"data":"Task(s) ID(s) 42 has been deleted"}`} {
		c, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
		state, err := c.Delete(context.Background(), owned())
		assertCode(t, err, Protocol)
		if state != "" {
			t.Fatal("failed deletion became acknowledgement")
		}
	}
}

func reportFixture() (string, [32]byte) {
	digest := sha256.Sum256([]byte("synthetic attachment"))
	return `{"info":{"id":41,"category":"file","CAPE_current_commit":"` + Revision + `"},"target":{"category":"file","file":{"sha256":"` + hex.EncodeToString(digest[:]) + `"}},"signatures":[]}`, digest
}

func TestReportIdentityAndSchema(t *testing.T) {
	valid, digest := reportFixture()
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"valid", valid, true},
		{"task-mismatch", strings.Replace(valid, `"id":41`, `"id":42`, 1), false},
		{"hash-mismatch", strings.Replace(valid, hex.EncodeToString(digest[:]), strings.Repeat("0", 64), 1), false},
		{"unknown-producer-commit", strings.Replace(valid, Revision, "unknown", 1), true},
		{"wrong-category", strings.ReplaceAll(valid, `"file"`, `"url"`), false},
		{"duplicate-task", strings.Replace(valid, `"id":41`, `"id":42,"id":41`, 1), false},
		{"nonfinite", strings.Replace(valid, `"signatures":[]`, `"score":1e999`, 1), false},
		{"nan", strings.Replace(valid, `"signatures":[]`, `"score":NaN`, 1), false},
		{"missing-envelope", `{"error":false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/apiv2/tasks/get/report/41/json/" {
					t.Error("unexpected report route")
				}
				_, _ = io.WriteString(w, tc.body)
			})
			report, err := c.Report(context.Background(), owned(), digest)
			if tc.valid {
				if err != nil || report == nil || report.Document()["signatures"] == nil {
					t.Fatal("valid report rejected")
				}
				if strings.Contains(fmt.Sprintf("%+v %#v", report, report), "signatures") {
					t.Fatal("report formatting leaked document")
				}
			} else {
				assertCode(t, err, Protocol)
				if report != nil {
					t.Fatal("invalid report returned")
				}
			}
		})
	}
}

func TestResponseSizeAndDepth(t *testing.T) {
	valid, digest := reportFixture()
	for _, size := range []int{MaxReport, MaxReport + 1} {
		body := valid + strings.Repeat(" ", size-len(valid))
		c, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
		_, err := c.Report(context.Background(), owned(), digest)
		if size == MaxReport {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			assertCode(t, err, TooLarge)
		}
	}
	for _, depth := range []int{64, 65} {
		body := []byte(`{"x":` + strings.Repeat("[", depth-1) + `0` + strings.Repeat("]", depth-1) + `}`)
		_, err := jsonDocument(body, nil)
		if depth == 64 {
			if err != nil {
				t.Fatal("depth 64 rejected")
			}
		} else {
			assertCode(t, err, Protocol)
		}
	}
}

func TestDeadlineAndCloseCancelRequests(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		started := make(chan struct{})
		c, _ := fixture(t, func(_ http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() })
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		result := make(chan error, 1)
		go func() { _, err := c.Status(ctx, owned()); result <- err }()
		<-started
		if closeClient {
			_ = c.Close()
		}
		select {
		case err := <-result:
			assertCode(t, err, Deadline)
		case <-time.After(2 * time.Second):
			t.Fatal("request deadline/Close did not cancel")
		}
		cancel()
	}
}

type blockedSource struct {
	closed chan struct{}
	once   sync.Once
}

func (s *blockedSource) Read([]byte) (int, error) { <-s.closed; return 0, io.ErrClosedPipe }
func (s *blockedSource) Close() error             { s.once.Do(func() { close(s.closed) }); return nil }

func TestUploadCancellationClosesSource(t *testing.T) {
	c, _ := fixture(t, func(_ http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s := &blockedSource{closed: make(chan struct{})}
	start := time.Now()
	result, err := c.Submit(ctx, s, 1, marker)
	if err == nil || !result.UnknownDebt || time.Since(start) > 2*time.Second {
		t.Fatal("blocked upload did not cancel with uncertainty")
	}
	select {
	case <-s.closed:
	default:
		t.Fatal("upload source not closed")
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"0", 5 * time.Second}, {"10", 10 * time.Second}, {"300", 5 * time.Minute}, {"999999999999", 5 * time.Minute},
		{"bad", 5 * time.Second}, {"-1", 5 * time.Second}, {now.Add(time.Minute).Format(http.TimeFormat), time.Minute},
		{now.Add(time.Hour).Format(http.TimeFormat), 5 * time.Minute}, {now.Add(-time.Hour).Format(http.TimeFormat), 5 * time.Second},
	} {
		if got := retryAfter(tc.value, now); got != tc.want {
			t.Fatalf("Retry-After %q = %s want %s", tc.value, got, tc.want)
		}
	}
}

func TestPinnedDestinationWithoutDNS(t *testing.T) {
	c, cfg := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"error":false,"data":"pending"}`)
	})
	// The fixture certificate contains example.com. A DNS lookup for that name
	// would leave this listener; the pinned dial must still reach this fixture.
	cfg.Origin = "https://example.com:" + fmt.Sprint(cfg.AllowedDestination.Port())
	pinned, err := New(cfg, c.credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	status, err := pinned.Status(context.Background(), owned())
	if err != nil || status != "pending" {
		t.Fatalf("pinned destination failed: %v", err)
	}
}

func TestConnectionFailureIsUncertain(t *testing.T) {
	c, cfg := fixture(t, func(http.ResponseWriter, *http.Request) {})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	cfg.AllowedDestination = netip.MustParseAddrPort(addr)
	cfg.Origin = "https://" + addr
	failed, err := New(cfg, c.credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer failed.Close()
	result, err := failed.Submit(context.Background(), source("x"), 1, marker)
	assertCode(t, err, Transport)
	if result.NoBytesSent || !result.UnknownDebt {
		t.Fatal("transport failure incorrectly authorized replay")
	}
}
