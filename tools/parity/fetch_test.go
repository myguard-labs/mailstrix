package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const fetchTestOrigin = "https://example.invalid"

type fetchFixture struct {
	m      manifest
	raw    []byte
	p      fetchPlan
	bodies map[string][]byte
}

func inertFetchFixture(t *testing.T) fetchFixture {
	t.Helper()
	m, _, root := generated(t)
	// Only the metadata is external. All bytes are produced by our inert generator.
	m.Sources[0].Kind = "external"
	m.Sources[0].Privacy = "restricted"
	m.Sources[0].Redistribution = "local-only"
	for i := range m.Samples {
		m.Samples[i].Partition = "external-clean"
		m.Samples[i].Truth.Basis = "independent"
	}
	raw, err := encodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	f := fetchFixture{m: m, raw: raw, p: fetchPlan{SchemaVersion: 1, ManifestSHA256: digest(raw)}, bodies: make(map[string][]byte)}
	for i, s := range m.Samples {
		url := fetchTestOrigin + "/sample-" + s.ID
		b, err := readSample(root, s)
		if err != nil {
			t.Fatal(err)
		}
		f.bodies[url] = b
		f.p.Requests = append(f.p.Requests, fetchRequest{SampleID: m.Samples[i].ID, URL: url})
	}
	return f
}

type fetchRoundTripper func(*http.Request) (*http.Response, error)

func (f fetchRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (f fetchFixture) client(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: fetchRoundTripper(func(r *http.Request) (*http.Response, error) {
		b, ok := f.bodies[r.URL.String()]
		if !ok {
			t.Fatalf("unexpected synthetic URL %q", r.URL)
		}
		if r.Method != "GET" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("request policy changed")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: int64(len(b)), Body: io.NopCloser(bytes.NewReader(b)), Request: r}, nil
	})}
}

func (f fetchFixture) ops(t *testing.T) fetchIO {
	ops := defaultFetchIO()
	client := f.client(t)
	ops.get = func(ctx context.Context, u string, s sample) ([]byte, error) { return fetchBytes(ctx, client, u, s) }
	return ops
}

func (f fetchFixture) urls(t *testing.T) []string {
	t.Helper()
	urls, _, err := prepareFetch(f.m, digest(f.raw), f.p, []string{fetchTestOrigin})
	if err != nil {
		t.Fatal(err)
	}
	return urls
}

func (f fetchFixture) args(t *testing.T, out string) []string {
	t.Helper()
	dir := t.TempDir()
	m := filepath.Join(dir, "manifest.json")
	p := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(m, f.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(f.p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"-manifest", m, "-fetch-plan", p, "-allow-origin", fetchTestOrigin, "-out", out}
}

func requireEmptyFetchParent(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failure left published or staging data: %d entries", len(entries))
	}
}

func TestFetchRoundTrip(t *testing.T) {
	if !fetchPlatformSupported() {
		t.Skip("Linux-only publication")
	}
	f := inertFetchFixture(t)
	for run := 0; run < 2; run++ {
		out := filepath.Join(t.TempDir(), "corpus")
		var log bytes.Buffer
		if code := fetchCLI(f.args(t, out), &log, f.ops(t)); code != 0 {
			t.Fatalf("exit %d: %s", code, &log)
		}
		if !strings.Contains(log.String(), "no scans performed") {
			t.Fatal("missing outcome")
		}
		root, err := os.OpenRoot(out)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })
		b, err := root.ReadFile("manifest.json")
		if err != nil || !bytes.Equal(b, f.raw) {
			t.Fatal("manifest bytes changed")
		}
		if code := cli([]string{"check", "-manifest", filepath.Join(out, "manifest.json"), "-corpus-root", out}, io.Discard, io.Discard); code != 0 {
			t.Fatalf("check exit %d", code)
		}
		if err := requireSynthetic(f.m); err == nil {
			t.Fatal("external manifest executable by run")
		}
		for _, name := range append([]string{".", "manifest.json"}, f.m.Samples[0].Locator) {
			info, err := root.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			want := os.FileMode(0o600)
			if info.IsDir() {
				want = 0o700
			}
			if info.Mode().Perm() != want {
				t.Fatalf("permissions %o want %o", info.Mode().Perm(), want)
			}
		}
	}
}

func TestFetchPlanStrictSchema(t *testing.T) {
	f := inertFetchFixture(t)
	b, err := json.Marshal(f.p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeFetchPlan(b); err != nil {
		t.Fatal(err)
	}
	boundary := append(append([]byte{}, b...), bytes.Repeat([]byte(" "), maxManifest-len(b))...)
	if _, err := decodeFetchPlan(boundary); err != nil {
		t.Fatal("exact plan byte limit rejected")
	}
	if _, err := decodeFetchPlan(append(boundary, ' ')); err == nil {
		t.Fatal("plan byte limit overflow accepted")
	}
	for name, b := range map[string][]byte{
		"unknown":       []byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"secret":0`, 1)),
		"duplicate":     []byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		"case":          []byte(strings.Replace(string(b), `"requests"`, `"Requests"`, 1)),
		"missing":       []byte(strings.Replace(string(b), `"schema_version":1,`, "", 1)),
		"version":       []byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":2`, 1)),
		"request field": []byte(strings.Replace(string(b), `"sample_id"`, `"sample"`, 1)),
		"missing url":   []byte(`{"schema_version":1,"manifest_sha256":"x","requests":[{"sample_id":"x"}]}`),
		"trailing":      append(append([]byte{}, b...), []byte(" {}")...),
		"size":          bytes.Repeat([]byte(" "), maxManifest+1),
		"depth":         []byte(strings.Repeat("[", 18) + strings.Repeat("]", 18)),
		"type":          []byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":"1"`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeFetchPlan(b); err == nil {
				t.Fatal("malformed fetch plan accepted")
			}
		})
	}
}

func TestFetchReferencesAndDestinations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fetchFixture)
	}{
		{"manifest binding", func(f *fetchFixture) { f.p.ManifestSHA256 = strings.Repeat("0", 64) }},
		{"missing", func(f *fetchFixture) { f.p.Requests = f.p.Requests[:1] }},
		{"extra", func(f *fetchFixture) {
			f.p.Requests = append(f.p.Requests, fetchRequest{SampleID: "extra", URL: fetchTestOrigin + "/extra"})
		}},
		{"duplicate", func(f *fetchFixture) { f.p.Requests[1].SampleID = f.p.Requests[0].SampleID }},
		{"unknown", func(f *fetchFixture) { f.p.Requests[0].SampleID = "unknown" }},
		{"duplicate locator", func(f *fetchFixture) { f.m.Samples[1].Locator = f.m.Samples[0].Locator }},
		{"prefix", func(f *fetchFixture) { f.m.Samples[1].Locator = f.m.Samples[0].Locator + "/child" }},
		{"manifest", func(f *fetchFixture) { f.m.Samples[0].Locator = "manifest.json" }},
		{"manifest child", func(f *fetchFixture) { f.m.Samples[0].Locator = "manifest.json/child" }},
		{"traversal", func(f *fetchFixture) { f.m.Samples[0].Locator = "../outside" }},
		{"absolute", func(f *fetchFixture) { f.m.Samples[0].Locator = "/outside" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := inertFetchFixture(t)
			tc.change(&f)
			if _, _, err := prepareFetch(f.m, digest(f.raw), f.p, []string{fetchTestOrigin}); err == nil {
				t.Fatal("invalid fetch references/destinations accepted")
			}
		})
	}
}

func TestFetchSizeLimits(t *testing.T) {
	f := inertFetchFixture(t)
	s := f.m.Samples[0]
	s.Size = maxSample
	f.m.Samples = nil
	f.p.Requests = nil
	for i := 0; i < maxFetchBytes/maxSample; i++ {
		a := s
		a.ID = "sample-" + strconv.Itoa(i)
		a.Locator = a.ID
		f.m.Samples = append(f.m.Samples, a)
		f.p.Requests = append(f.p.Requests, fetchRequest{SampleID: a.ID, URL: fetchTestOrigin + "/" + a.ID})
	}
	if _, total, err := prepareFetch(f.m, digest(f.raw), f.p, []string{fetchTestOrigin}); err != nil || total != maxFetchBytes {
		t.Fatalf("exact aggregate limit rejected: %d %v", total, err)
	}
	a := s
	a.ID = "over"
	a.Locator = "over"
	a.Size = 1
	a.SHA256 = digest([]byte("x"))
	f.m.Samples = append(f.m.Samples, a)
	f.p.Requests = append(f.p.Requests, fetchRequest{SampleID: a.ID, URL: fetchTestOrigin + "/over"})
	if _, _, err := prepareFetch(f.m, digest(f.raw), f.p, []string{fetchTestOrigin}); err == nil {
		t.Fatal("aggregate overflow accepted")
	}
	f.m.Samples = f.m.Samples[:1]
	f.p.Requests = f.p.Requests[:1]
	f.m.Samples[0].Size = maxSample + 1
	if _, _, err := prepareFetch(f.m, digest(f.raw), f.p, []string{fetchTestOrigin}); err == nil {
		t.Fatal("per-file overflow accepted")
	}
}

func TestFetchOriginPolicy(t *testing.T) {
	for _, raw := range []string{
		"http://example.invalid/a", "https://other.invalid/a", "https://example.invalid:443/a",
		"https://u:p@example.invalid/a", "https://example.invalid/a?token=private", "https://example.invalid/a?",
		"https://example.invalid/a#private", "https://example.invalid/a#", "https://EXAMPLE.invalid/a",
		"https://example.invalid./a", "https://example.invalid:0/a", "https://example.invalid:0443/a",
		"https://example.invalid:65536/a", "https://example.invalid:/a", "https://*.invalid/a",
		"https://[fe80::1%25eth0]/a", "https:example.invalid/a", "https://bad_host.invalid/a",
	} {
		t.Run(raw, func(t *testing.T) {
			f := inertFetchFixture(t)
			f.p.Requests[0].URL = raw
			if _, _, err := prepareFetch(f.m, digest(f.raw), f.p, []string{fetchTestOrigin}); err == nil {
				t.Fatal("unapproved origin or URL accepted")
			}
		})
	}
	for _, allowed := range [][]string{nil, {"https://example.invalid/"}, {"https://example.invalid/path"}, {"https://*.invalid"}, {"http://example.invalid"}} {
		f := inertFetchFixture(t)
		if _, _, err := prepareFetch(f.m, digest(f.raw), f.p, allowed); err == nil {
			t.Fatal("invalid origin allowlist accepted")
		}
	}
}

func TestFetchIntegrityFailureCleanup(t *testing.T) {
	if !fetchPlatformSupported() {
		t.Skip("Linux-only publication")
	}
	for _, kind := range []string{"checksum", "truncated", "oversized", "transport"} {
		t.Run(kind, func(t *testing.T) {
			f := inertFetchFixture(t)
			urls := f.urls(t)
			ops := f.ops(t)
			get := ops.get
			calls := 0
			ops.get = func(ctx context.Context, u string, s sample) ([]byte, error) {
				calls++
				if calls == 2 {
					switch kind {
					case "checksum":
						s.SHA256 = strings.Repeat("0", 64)
					case "truncated":
						f.bodies[u] = f.bodies[u][:len(f.bodies[u])-1]
					case "oversized":
						f.bodies[u] = append(f.bodies[u], 0)
					case "transport":
						return nil, errors.New("PRIVATE_ERROR")
					}
				}
				return get(ctx, u, s)
			}
			parent := t.TempDir()
			err := fetchCorpus(context.Background(), f.m, f.raw, urls, filepath.Join(parent, "out"), ops)
			if err == nil || calls != 2 {
				t.Fatalf("bad later sample accepted or earlier failure: %v calls=%d", err, calls)
			}
			requireEmptyFetchParent(t, parent)
		})
	}
}

func TestFetchExistingDestination(t *testing.T) {
	if !fetchPlatformSupported() {
		t.Skip("Linux-only publication")
	}
	for _, kind := range []string{"empty", "nonempty", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := inertFetchFixture(t)
			parent := t.TempDir()
			out := filepath.Join(parent, "out")
			if kind == "symlink" {
				if err := os.Symlink(t.TempDir(), out); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(out, 0o700); err != nil {
					t.Fatal(err)
				}
				if kind == "nonempty" {
					if err := os.WriteFile(filepath.Join(out, "sentinel"), []byte("keep"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			ops := f.ops(t)
			ops.get = func(context.Context, string, sample) ([]byte, error) {
				t.Fatal("network before existing destination check")
				return nil, nil
			}
			if err := fetchCorpus(context.Background(), f.m, f.raw, f.urls(t), out, ops); err == nil {
				t.Fatal("existing destination accepted")
			}
			info, err := os.Lstat(out)
			if err != nil {
				t.Fatal("destination removed")
			}
			if kind == "symlink" && info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("symlink replaced")
			}
			if kind == "nonempty" {
				b, err := os.ReadFile(filepath.Join(out, "sentinel"))
				if err != nil || string(b) != "keep" {
					t.Fatal("sentinel replaced")
				}
			}
		})
	}
}

func TestFetchPublicationRace(t *testing.T) {
	if !fetchPlatformSupported() {
		t.Skip("Linux-only publication")
	}
	f := inertFetchFixture(t)
	ops := f.ops(t)
	ops.publish = func(parent *os.Root, stage, dest string) error {
		// An empty directory is the important case: ordinary rename can replace it.
		if err := parent.Mkdir(dest, 0o700); err != nil {
			return err
		}
		return publishFetch(parent, stage, dest)
	}
	parent := t.TempDir()
	out := filepath.Join(parent, "out")
	if err := fetchCorpus(context.Background(), f.m, f.raw, f.urls(t), out, ops); err == nil {
		t.Fatal("racing destination replaced")
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 0 {
		t.Fatal("racing empty destination changed")
	}
	entries, err = os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatal("unpublished stage not cleaned")
	}
}

type faultyFetchWriter struct {
	writeErr, closeErr error
	short              bool
}

func (w faultyFetchWriter) Write(b []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if w.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (w faultyFetchWriter) Close() error { return w.closeErr }

func TestFetchIOFailuresAndCancellation(t *testing.T) {
	if !fetchPlatformSupported() {
		t.Skip("Linux-only publication")
	}
	for _, kind := range []string{"create", "write", "short", "close", "publish", "cancel", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			f := inertFetchFixture(t)
			ops := f.ops(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			private := errors.New("PRIVATE_ERROR")
			switch kind {
			case "create":
				ops.create = func(*os.Root, string) (io.WriteCloser, error) { return nil, private }
			case "write":
				ops.create = func(*os.Root, string) (io.WriteCloser, error) { return faultyFetchWriter{writeErr: private}, nil }
			case "short":
				ops.create = func(*os.Root, string) (io.WriteCloser, error) { return faultyFetchWriter{short: true}, nil }
			case "close":
				ops.create = func(*os.Root, string) (io.WriteCloser, error) { return faultyFetchWriter{closeErr: private}, nil }
			case "publish":
				ops.publish = func(*os.Root, string, string) error { return private }
			case "cancel":
				get := ops.get
				ops.get = func(ctx context.Context, u string, s sample) ([]byte, error) {
					b, err := get(ctx, u, s)
					cancel()
					return b, err
				}
			case "cleanup":
				ops.get = func(context.Context, string, sample) ([]byte, error) { return nil, private }
				ops.cleanup = func(*os.Root, string) error { return private }
			}
			parent := t.TempDir()
			err := fetchCorpus(ctx, f.m, f.raw, f.urls(t), filepath.Join(parent, "out"), ops)
			if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("error contract: %v", err)
			}
			if kind != "cleanup" {
				requireEmptyFetchParent(t, parent)
			} else {
				entries, e := os.ReadDir(parent)
				if e != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".parity-fetch-") {
					t.Fatal("cleanup failure lost private staging artifact")
				}
				info, e := entries[0].Info()
				if e != nil || info.Mode().Perm() != 0o700 {
					t.Fatal("leftover staging directory not private")
				}
				if !strings.Contains(err.Error(), "cleanup failed") {
					t.Fatal("cleanup uncertainty not reported")
				}
			}
		})
	}
}

func TestFetchCLIPrivacyAndPreflight(t *testing.T) {
	f := inertFetchFixture(t)
	ops := f.ops(t)
	ops.get = func(context.Context, string, sample) ([]byte, error) {
		t.Fatal("network reached on invalid input")
		return nil, nil
	}
	for _, args := range [][]string{{"-secret=PRIVATE"}, {"-manifest", "PRIVATE"}, {"PRIVATE"}} {
		var log bytes.Buffer
		if code := fetchCLI(args, &log, ops); code != 2 || strings.Contains(log.String(), "PRIVATE") {
			t.Fatalf("private flag error leaked: %d %s", code, &log)
		}
	}
	f.p.Requests[0].URL = "https://u:PRIVATE@example.invalid/a"
	parent := t.TempDir()
	var log bytes.Buffer
	if code := fetchCLI(f.args(t, filepath.Join(parent, "out")), &log, ops); code != 2 || strings.Contains(log.String(), "PRIVATE") {
		t.Fatalf("private URL leaked: %d %s", code, &log)
	}
	requireEmptyFetchParent(t, parent)
	if fetchPlatformSupported() {
		f = inertFetchFixture(t)
		ops = f.ops(t)
		ops.get = func(context.Context, string, sample) ([]byte, error) { return nil, errors.New("PRIVATE_URL_PATH_BODY") }
		log.Reset()
		if code := fetchCLI(f.args(t, filepath.Join(parent, "out")), &log, ops); code != 2 || strings.Contains(log.String(), "PRIVATE") {
			t.Fatalf("private I/O error leaked: %d %s", code, &log)
		}
		requireEmptyFetchParent(t, parent)
	}
}

func TestFetchCLIUnsupportedPlatformBeforeInputs(t *testing.T) {
	ops := defaultFetchIO()
	ops.platformSupported = false
	ops.get = func(context.Context, string, sample) ([]byte, error) {
		t.Fatal("unsupported platform reached acquisition")
		return nil, nil
	}
	// Missing paths prove that the platform outcome precedes local input reads.
	dir := t.TempDir()
	args := []string{"-manifest", filepath.Join(dir, "PRIVATE-manifest"), "-fetch-plan", filepath.Join(dir, "PRIVATE-plan"), "-out", filepath.Join(dir, "out"), "-allow-origin", fetchTestOrigin}
	var log bytes.Buffer
	if code := fetchCLI(args, &log, ops); code != 2 || log.String() != "fetch publication requires Linux\n" {
		t.Fatalf("unsupported platform diagnostic: exit=%d output=%q", code, log.String())
	}
	requireEmptyFetchParent(t, dir)
}
