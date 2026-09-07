package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxFetchBytes       = 256 << 20
	fetchRequestTimeout = 15 * time.Second
	fetchTimeout        = 10 * time.Minute
)

// A plan binds exact manifest bytes, not merely a reusable corpus name. URLs
// are acquisition instructions; the existing source references remain evidence.
type fetchPlan struct {
	SchemaVersion  int            `json:"schema_version"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	Requests       []fetchRequest `json:"requests"`
}

type fetchRequest struct {
	SampleID string `json:"sample_id"`
	URL      string `json:"url"`
}

func decodeFetchPlan(b []byte) (fetchPlan, error) {
	var p fetchPlan
	invalid := errors.New("invalid fetch plan")
	if len(b) > maxManifest {
		return p, invalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if err := checkJSON(d, 0); err != nil {
		return p, invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return p, invalid
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, invalid
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return p, invalid
	}
	var supplied, typed any
	if json.Unmarshal(b, &supplied) != nil || json.Unmarshal(canonical, &typed) != nil {
		return p, invalid
	}
	a, err := json.Marshal(supplied)
	if err != nil {
		return p, invalid
	}
	z, err := json.Marshal(typed)
	if err != nil || !bytes.Equal(a, z) || p.SchemaVersion != 1 {
		return p, invalid
	}
	return p, nil
}

// Preparation is pure: reject the entire plan before output or network I/O.
func prepareFetch(m manifest, hash string, p fetchPlan, origins []string) ([]string, int64, error) {
	if err := m.validate(); err != nil {
		return nil, 0, errors.New("invalid fetch manifest")
	}
	if p.SchemaVersion != 1 || p.ManifestSHA256 != hash || len(p.Requests) != len(m.Samples) {
		return nil, 0, errors.New("fetch plan does not match manifest")
	}
	allowed := make(map[string]bool, len(origins))
	for _, origin := range origins {
		u, err := fetchURL(origin)
		if err != nil || u.Path != "" || u.RawPath != "" {
			return nil, 0, errors.New("invalid allowed origin")
		}
		allowed[u.Scheme+"://"+u.Host] = true
	}
	if len(allowed) == 0 {
		return nil, 0, errors.New("fetch requires allowed origins")
	}
	requests := make(map[string]string, len(p.Requests))
	for _, request := range p.Requests {
		u, err := fetchURL(request.URL)
		if err != nil || !allowed[u.Scheme+"://"+u.Host] {
			return nil, 0, errors.New("fetch URL is not allowed")
		}
		if _, exists := requests[request.SampleID]; exists {
			return nil, 0, errors.New("duplicate fetch reference")
		}
		requests[request.SampleID] = request.URL
	}
	locators := make(map[string]bool, len(m.Samples))
	urls := make([]string, len(m.Samples))
	var total int64
	for i, s := range m.Samples {
		url, exists := requests[s.ID]
		if !exists {
			return nil, 0, errors.New("missing fetch reference")
		}
		urls[i] = url
		if s.Locator == "manifest.json" || strings.HasPrefix(s.Locator, "manifest.json/") || locators[s.Locator] {
			return nil, 0, errors.New("conflicting fetch destination")
		}
		locators[s.Locator] = true
		if s.Size > maxFetchBytes-total {
			return nil, 0, errors.New("fetch exceeds 256 MiB")
		}
		total += s.Size
	}
	for locator := range locators {
		for parent := path.Dir(locator); parent != "."; parent = path.Dir(parent) {
			if locators[parent] {
				return nil, 0, errors.New("conflicting fetch destination")
			}
		}
	}
	return urls, total, nil
}

type originFlags []string

func (f *originFlags) String() string         { return "" }
func (f *originFlags) Set(value string) error { *f = append(*f, value); return nil }

// File paths are explicit caller inputs. Diagnostics deliberately never include
// their values, the private manifest, URLs, or errors returned by I/O providers.
func readFetchJSON(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxManifest {
		return nil, errors.New("invalid fetch input file")
	}
	f, err := openFetchInput(name)
	if err != nil {
		return nil, errors.New("cannot open fetch input")
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxManifest {
		_ = f.Close()
		return nil, errors.New("invalid fetch input file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxManifest+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(b) > maxManifest {
		return nil, errors.New("cannot read fetch input")
	}
	return b, nil
}

func fetchCLI(args []string, stderr io.Writer, ops fetchIO) int {
	f := flag.NewFlagSet("fetch", flag.ContinueOnError)
	f.SetOutput(io.Discard) // flag errors may quote caller secrets.
	manifestPath := f.String("manifest", "", "existing v1 manifest")
	planPath := f.String("fetch-plan", "", "fetch plan v1")
	out := f.String("out", "", "new private output directory")
	var origins originFlags
	f.Var(&origins, "allow-origin", "exact HTTPS origin (repeatable)")
	if f.Parse(args) != nil || f.NArg() != 0 || *manifestPath == "" || *planPath == "" || *out == "" {
		printError(stderr, "fetch requires -manifest, -fetch-plan, -allow-origin and -out")
		return 2
	}
	raw, err := readFetchJSON(*manifestPath)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	m, hash, err := decodeManifest(bytes.NewReader(raw))
	if err != nil {
		printError(stderr, "invalid fetch manifest")
		return 2
	}
	b, err := readFetchJSON(*planPath)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	p, err := decodeFetchPlan(b)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	urls, total, err := prepareFetch(m, hash, p, origins)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	if err := fetchCorpus(ctx, m, raw, urls, *out, ops); err != nil {
		printError(stderr, err)
		return 2
	}
	if _, err := fmt.Fprintf(stderr, "published %d sample references (%d bytes); no scans performed\n", len(m.Samples), total); err != nil {
		printError(stderr, "fetch published; summary write failed")
		return 2
	}
	return 0
}

// Only these side effects are substituted by fault tests. No CLI option can
// replace network policy, publication semantics, or private file creation.
type fetchIO struct {
	get     func(context.Context, string, sample) ([]byte, error)
	create  func(*os.Root, string) (io.WriteCloser, error)
	publish func(*os.Root, string, string) error
	cleanup func(*os.Root, string) error
}

func defaultFetchIO() fetchIO {
	client := newFetchClient(netFetchDialer())
	return fetchIO{
		get: func(ctx context.Context, url string, s sample) ([]byte, error) {
			return fetchBytes(ctx, client, url, s)
		},
		create: func(root *os.Root, name string) (io.WriteCloser, error) {
			return root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		},
		publish: publishFetch,
		cleanup: func(root *os.Root, name string) error { return root.RemoveAll(name) },
	}
}

func writeFetchFile(root *os.Root, name string, data []byte, ops fetchIO) error {
	if err := root.MkdirAll(path.Dir(name), 0o700); err != nil {
		return errors.New("cannot create fetch directory")
	}
	f, err := ops.create(root, name)
	if err != nil {
		return errors.New("cannot create fetch file")
	}
	n, err := f.Write(data)
	closeErr := f.Close()
	if err != nil || n != len(data) || closeErr != nil {
		return errors.New("cannot write fetch file")
	}
	return nil
}

// The caller owns a stable output parent. Until no-replace publication succeeds,
// only this invocation's random sibling is ours to remove. Atomic visibility is
// provided, not crash durability. No scanner or comparator is called here.
func fetchCorpus(ctx context.Context, m manifest, raw []byte, urls []string, out string, ops fetchIO) (result error) {
	if !fetchPlatformSupported() {
		return errors.New("fetch publication requires Linux")
	}
	if err := ctx.Err(); err != nil {
		return errors.New("fetch cancelled")
	}
	clean := filepath.Clean(out)
	name := filepath.Base(clean)
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return errors.New("invalid fetch destination")
	}
	parent, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return errors.New("cannot open fetch destination parent")
	}
	defer func() { _ = parent.Close() }()
	if _, err := parent.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fetch destination already exists or is unavailable")
	}
	stageName := ".parity-fetch-" + rand.Text()
	if err := parent.Mkdir(stageName, 0o700); err != nil {
		return errors.New("cannot create fetch staging directory")
	}
	defer func() {
		if stageName != "" {
			if err := ops.cleanup(parent, stageName); err != nil {
				result = errors.New("fetch failed; private staging cleanup failed")
			}
		}
	}()
	stage, err := parent.OpenRoot(stageName)
	if err != nil {
		return errors.New("cannot open fetch staging directory")
	}
	defer func() { _ = stage.Close() }()
	for i, s := range m.Samples {
		if ctx.Err() != nil {
			return errors.New("fetch cancelled")
		}
		b, err := ops.get(ctx, urls[i], s)
		if err != nil {
			return errors.New("fetch sample failed")
		}
		if ctx.Err() != nil {
			return errors.New("fetch cancelled")
		}
		if err := writeFetchFile(stage, s.Locator, b, ops); err != nil {
			return err
		}
	}
	if err := writeFetchFile(stage, "manifest.json", raw, ops); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("fetch cancelled")
	}
	if err := ops.publish(parent, stageName, name); err != nil {
		return errors.New("fetch publication failed")
	}
	stageName = ""
	return nil
}
