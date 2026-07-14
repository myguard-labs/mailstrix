package verdict

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func m(rule string, meta map[string]string) Match {
	return Match{Rule: rule, Meta: meta}
}

// --- Actionable: the log-only contract ------------------------------------

func TestActionableDropsCanary(t *testing.T) {
	in := []Match{
		m("canary", map[string]string{"mailstrix_canary": "1"}),
		m("real", nil),
	}
	got := Actionable(in)
	if len(got) != 1 || got[0].Rule != "real" {
		t.Fatalf("Actionable = %+v, want just [real] — a canary rule must never be actionable", got)
	}
}

func TestActionableDropsAllowlisted(t *testing.T) {
	in := []Match{
		m("benign", map[string]string{"mailstrix_allow": "1"}),
		m("real", nil),
	}
	got := Actionable(in)
	if len(got) != 1 || got[0].Rule != "real" {
		t.Fatalf("Actionable = %+v, want just [real]", got)
	}
}

func TestActionableAllLogOnlyYieldsNothing(t *testing.T) {
	in := []Match{
		m("canary", map[string]string{"mailstrix_canary": "1"}),
		m("benign", map[string]string{"mailstrix_allow": "1"}),
	}
	if got := Actionable(in); len(got) != 0 {
		t.Fatalf("Actionable = %+v, want empty — nothing here is actionable", got)
	}
}

// Only the exact value "1" is log-only. A rule tagged mailstrix_canary=0 (or
// "true", or anything else) is a NORMAL rule — treating it as log-only would
// silently disarm a real detection.
func TestActionableOnlyExactlyOneIsLogOnly(t *testing.T) {
	for _, v := range []string{"0", "", "true", "yes", "2"} {
		in := []Match{m("r", map[string]string{"mailstrix_canary": v})}
		if got := Actionable(in); len(got) != 1 {
			t.Errorf("mailstrix_canary=%q was treated as log-only; only \"1\" may be", v)
		}
	}
}

func TestActionablePreservesOrderAndDoesNotMutateInput(t *testing.T) {
	in := []Match{
		m("a", nil),
		m("canary", map[string]string{"mailstrix_canary": "1"}),
		m("b", nil),
		m("c", nil),
	}
	got := Actionable(in)
	if len(got) != 3 || got[0].Rule != "a" || got[1].Rule != "b" || got[2].Rule != "c" {
		t.Fatalf("Actionable = %+v, want [a b c] in order", got)
	}
	if len(in) != 4 || in[1].Rule != "canary" {
		t.Fatalf("Actionable mutated its input: %+v", in)
	}
}

func TestActionableEmptyAndNilMeta(t *testing.T) {
	if got := Actionable(nil); got != nil {
		t.Fatalf("Actionable(nil) = %+v, want nil", got)
	}
	in := []Match{m("r", nil)} // nil Meta must not panic
	if got := Actionable(in); len(got) != 1 {
		t.Fatalf("Actionable = %+v", got)
	}
}

// --- For: verdict shaping -------------------------------------------------

func TestForCleanIsNotMalicious(t *testing.T) {
	v := For(nil)
	if v.Malicious || v.Family != "" || v.Confidence != "" || len(v.Rules) != 0 {
		t.Fatalf("For(nil) = %+v, want the zero verdict", v)
	}
}

func TestForFamilyBearing(t *testing.T) {
	v := For([]Match{m("R", map[string]string{"family": "Emotet"})})
	if !v.Malicious || v.Family != "Emotet" || v.Confidence != "family" {
		t.Fatalf("For = %+v, want malicious/Emotet/family", v)
	}
}

func TestForGenericRuleHasNoFamily(t *testing.T) {
	v := For([]Match{m("SUSP_generic", nil)})
	if !v.Malicious || v.Family != "" || v.Confidence != "rule" {
		t.Fatalf("For = %+v, want malicious with confidence=rule and no family", v)
	}
}

func TestForFirstFamilyBearingWins(t *testing.T) {
	v := For([]Match{
		m("generic", nil),
		m("R1", map[string]string{"family": "Emotet"}),
		m("R2", map[string]string{"family": "Qakbot"}),
	})
	if v.Family != "Emotet" {
		t.Fatalf("Family = %q, want Emotet (the first family-bearing match)", v.Family)
	}
	if len(v.Rules) != 3 {
		t.Fatalf("Rules = %v, want all three (generic rules still count toward the hit)", v.Rules)
	}
}

func TestForFamilyKeyPriority(t *testing.T) {
	// family > malware_family > actor.
	v := For([]Match{m("R", map[string]string{"actor": "APT1", "malware_family": "Qakbot", "family": "Emotet"})})
	if v.Family != "Emotet" {
		t.Fatalf("Family = %q, want Emotet (key priority)", v.Family)
	}
	v = For([]Match{m("R", map[string]string{"actor": "APT1", "malware_family": "Qakbot"})})
	if v.Family != "Qakbot" {
		t.Fatalf("Family = %q, want Qakbot", v.Family)
	}
	v = For([]Match{m("R", map[string]string{"actor": "APT1"})})
	if v.Family != "APT1" {
		t.Fatalf("Family = %q, want APT1", v.Family)
	}
}

func TestForBlankFamilyMetaIsNotAFamily(t *testing.T) {
	v := For([]Match{m("R", map[string]string{"family": "   "})})
	if v.Family != "" || v.Confidence != "rule" {
		t.Fatalf("For = %+v — whitespace is not a family", v)
	}
}

// --- Client ---------------------------------------------------------------

func TestClientScanDecodesMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scan" {
			t.Errorf("path = %q, want /scan", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "payload" {
			t.Errorf("body = %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Response{Matches: []Match{m("R", nil)}})
	}))
	defer srv.Close()

	got, err := NewClient(srv.URL, "", "test/1", time.Second).Scan(t.Context(), "", []byte("payload"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || got[0].Rule != "R" {
		t.Fatalf("matches = %+v", got)
	}
}

func TestClientOmitsTokenHeaderWhenEmpty(t *testing.T) {
	// A token-less strixd must not receive an empty X-MAILSTRIX-Token header.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["X-Mailstrix-Token"]; ok {
			t.Error("token header sent despite an empty token")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Response{})
	}))
	defer srv.Close()

	if _, err := NewClient(srv.URL, "", "test/1", time.Second).Scan(t.Context(), "", []byte("x")); err != nil {
		t.Fatalf("Scan: %v", err)
	}
}

// The token is a shared secret. Following a redirect would copy the header onto
// the redirect target — possibly another host — leaking it.
func TestClientDoesNotFollowRedirectsAndLeakTheToken(t *testing.T) {
	var leaked bool
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-MAILSTRIX-Token") != "" {
			leaked = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/scan", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()

	_, err := NewClient(redir.URL, "s3cret", "test/1", time.Second).Scan(t.Context(), "", []byte("x"))
	if err == nil {
		t.Fatal("Scan followed a redirect instead of erroring")
	}
	if leaked {
		t.Fatal("the shared token was leaked to the redirect target")
	}
}

func TestClientNon200IsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "kaboom")
	}))
	defer srv.Close()

	if _, err := NewClient(srv.URL, "", "test/1", time.Second).Scan(t.Context(), "", []byte("x")); err == nil {
		t.Fatal("a 500 must be an error, not a clean scan")
	}
}

func TestClientTimeoutIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := NewClient(srv.URL, "", "test/1", 100*time.Millisecond).Scan(context.Background(), "", []byte("x"))
	if err == nil {
		t.Fatal("want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s — the client timeout did not bound the call", elapsed)
	}
}

func TestClientCallerContextCancels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := NewClient(srv.URL, "", "test/1", time.Minute).Scan(ctx, "", []byte("x")); err == nil {
		t.Fatal("want a cancellation error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s — the caller's context did not bound the call", elapsed)
	}
}
