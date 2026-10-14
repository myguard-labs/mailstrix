package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yara "github.com/hillu/go-yara/v4"
	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func TestMakeRecordCountsEveryMatchMetaAndSerializedByte(t *testing.T) {
	matches := []ms.Match{
		{Rule: "one", Namespace: "n", Tags: []string{"tag"}, Meta: map[string]string{"k": "value"}},
		{Rule: "two", Meta: map[string]string{"x": "y", "long": "z"}},
	}
	r := makeRecord("sample", []byte("body"), matches, "", "hit")
	wantJSON, err := json.Marshal(matches)
	if err != nil {
		t.Fatal(err)
	}
	if r.MatchCount != 2 || r.MetaPairs != 3 || r.MetaKeyValueBytes != 13 || r.MatchesJSONBytes != len(wantJSON) {
		t.Fatalf("wrong aggregation: %+v want matches=2 pairs=3 meta-bytes=13 json=%d", r, len(wantJSON))
	}
	if r.ModeledGoValueLowerBound <= r.MetaKeyValueBytes || r.SecondStatus != "hit" {
		t.Fatalf("retained/cache-hit evidence missing: %+v", r)
	}
}

func TestSummarizeCoversZeroOneMultiAndWorstIdentity(t *testing.T) {
	records := []record{
		{Path: "zero", MatchCount: 0, MatchesJSONBytes: 2, ModeledGoValueLowerBound: 0},
		{Path: "one", MatchCount: 1, MatchesJSONBytes: 20, MetaPairs: 1, MetaKeyValueBytes: 3, ModeledGoValueLowerBound: 80},
		{Path: "multi", MatchCount: 4, MatchesJSONBytes: 90, MetaPairs: 2, MetaKeyValueBytes: 9, ModeledGoValueLowerBound: 300},
	}
	s := summarize(records)
	if s.Records != 3 || s.ZeroMatch != 1 || s.OneMatch != 1 || s.MultiMatch != 1 || s.WithMeta != 2 {
		t.Fatalf("wrong category totals: %+v", s)
	}
	if s.WorstJSON.Path != "multi" || s.WorstModeledGo.Path != "multi" || s.MatchCount.Max != 4 || s.MetaBytes.Max != 9 {
		t.Fatalf("wrong distributions/worst identity: %+v", s)
	}
}

func TestDistributionUsesNearestRankBoundaries(t *testing.T) {
	t.Run("n2 p50", func(t *testing.T) {
		q := distribution([]int{2, 1})
		if q != (quantiles{Min: 1, P50: 1, P90: 2, P95: 2, P99: 2, Max: 2}) {
			t.Fatalf("n=2 nearest-rank quantiles: %+v", q)
		}
	})

	t.Run("n100 percentiles", func(t *testing.T) {
		values := make([]int, 100)
		for i := range values {
			values[i] = 100 - i
		}
		q := distribution(values)
		if q != (quantiles{Min: 1, P50: 50, P90: 90, P95: 95, P99: 99, Max: 100}) {
			t.Fatalf("n=100 nearest-rank quantiles: %+v", q)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if q := distribution(nil); q != (quantiles{}) {
			t.Fatalf("empty distribution: %+v", q)
		}
	})

	t.Run("singleton", func(t *testing.T) {
		if q := distribution([]int{7}); q != (quantiles{Min: 7, P50: 7, P90: 7, P95: 7, P99: 7, Max: 7}) {
			t.Fatalf("singleton distribution: %+v", q)
		}
	})

	t.Run("duplicates", func(t *testing.T) {
		q := distribution([]int{9, 4, 4, 4, 1})
		if q != (quantiles{Min: 1, P50: 4, P90: 9, P95: 9, P99: 9, Max: 9}) {
			t.Fatalf("duplicate distribution: %+v", q)
		}
	})
}

func TestRequestUsesProductionCacheAndPreservesFullMatches(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "fixture.yar")
	source := `rule One : first { meta: family = "alpha" strings: $a = "trigger" condition: $a }
rule Two : second { meta: score = 7 strings: $a = "trigger" condition: $a }`
	if err := os.WriteFile(rules, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &ms.Config{RulesDir: dir, ScanTimeout: time.Second, MaxBody: 1024, MaxConcurrent: 1, MaxInflight: 2, CacheTTL: time.Minute, CacheSize: 2, Effort: 10, EffortMax: 10}
	cfg.Finalize()
	scanner, err := ms.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	server := ms.NewServer(cfg, scanner)
	first, firstStatus, err := request(server, []byte("trigger"), "sample.bin")
	if err != nil {
		t.Fatal(err)
	}
	second, secondStatus, err := request(server, []byte("trigger"), "sample.bin")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(first.Matches)
	got, _ := json.Marshal(second.Matches)
	if firstStatus != "" || secondStatus != "hit" || string(got) != string(want) || len(second.Matches) != 2 {
		t.Fatalf("cache parity/status mismatch first=%q second=%q matches=%s want=%s", firstStatus, secondStatus, got, want)
	}
	if second.Matches[0].Meta["family"] != "alpha" || second.Matches[1].Meta["score"] != "7" {
		t.Fatalf("cache hit lost Meta: %+v", second.Matches)
	}
}

func TestRequestRejectsHTTPFailureAndMalformedJSON(t *testing.T) {
	for _, tc := range []struct {
		name  string
		serve func(http.ResponseWriter)
	}{
		{"status", func(w http.ResponseWriter) { http.Error(w, "no", http.StatusBadRequest) }},
		{"json", func(w http.ResponseWriter) { _, _ = w.Write([]byte("{")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { tc.serve(w) })
			if _, _, err := request(h, nil, "bad\r\nname"); err == nil {
				t.Fatal("malformed response unexpectedly accepted")
			}
		})
	}
}

func TestMeasurePathsSeparatesEveryUncachedOutcome(t *testing.T) {
	root := t.TempDir()
	names := []string{"first-error", "first-degraded", "second-error", "second-degraded", "second-miss", "changed", "good"}
	paths := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	calls := make(map[string]int)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		name := string(body)
		calls[name]++
		second := calls[name] == 2
		if (name == "first-error" && !second) || (name == "second-error" && second) {
			http.Error(w, "failed", http.StatusBadRequest)
			return
		}
		response := scanResponse{Matches: []ms.Match{{Rule: "one"}}}
		if (name == "first-degraded" && !second) || (name == "second-degraded" && second) {
			response.Degraded = "error"
		}
		if name == "changed" && second {
			response.Matches = append(response.Matches, ms.Match{Rule: "two"})
		}
		if second && name != "second-miss" {
			w.Header().Set("X-MAILSTRIX-Cache", "hit")
		}
		_ = json.NewEncoder(w).Encode(response)
	})
	records, uncached, err := measurePaths(handler, root, paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Path != "good" || len(uncached) != 6 {
		t.Fatalf("records=%+v uncached=%+v", records, uncached)
	}
	wantReasons := []string{"first scan:", "first scan degraded:", "second scan:", "second scan status=", "second scan status=", "cache hit changed matches"}
	for i, want := range wantReasons {
		if !strings.Contains(uncached[i].Reason, want) || uncached[i].SHA256 == "" {
			t.Fatalf("uncached[%d]=%+v want %q", i, uncached[i], want)
		}
	}
	if _, _, err := measurePaths(handler, root, []string{filepath.Join(root, "missing")}); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("missing input error=%v", err)
	}
}

func TestCorpusManifestIsRecursiveStableAndContentBound(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b"), []byte("bb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, size, first, err := corpusManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || size != 3 || filepath.Base(paths[0]) != "b" || first == "" {
		t.Fatalf("unexpected manifest paths=%v size=%d hash=%q", paths, size, first)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "a"), []byte("A"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, second, err := corpusManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("content mutation did not change manifest identity")
	}
}

func TestCorpusManifestReportsEveryFilesystemFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalWalk, originalInfo := walkCorpus, corpusEntryInfo
	originalHash, originalRelative := hashCorpusFile, relativeCorpusPath
	t.Cleanup(func() {
		walkCorpus, corpusEntryInfo = originalWalk, originalInfo
		hashCorpusFile, relativeCorpusPath = originalHash, originalRelative
	})

	want := errors.New("fixture failure")
	tests := []struct {
		name string
		set  func()
	}{
		{"walk", func() { walkCorpus = func(string, fs.WalkDirFunc) error { return want } }},
		{"info", func() { corpusEntryInfo = func(os.DirEntry) (os.FileInfo, error) { return nil, want } }},
		{"hash", func() { hashCorpusFile = func(string) (string, int64, error) { return "", 0, want } }},
		{"relative", func() { relativeCorpusPath = func(string, string) (string, error) { return "", want } }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			walkCorpus, corpusEntryInfo = originalWalk, originalInfo
			hashCorpusFile, relativeCorpusPath = originalHash, originalRelative
			tc.set()
			if _, _, _, err := corpusManifest(root); !errors.Is(err, want) {
				t.Fatalf("error=%v want %v", err, want)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestHashReaderReportsReadFailure(t *testing.T) {
	if _, _, err := hashReader(failingReader{}); err == nil {
		t.Fatal("read failure unexpectedly accepted")
	}
}

func TestRunMeasuresZeroAndMultiHitCacheEntries(t *testing.T) {
	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules")
	corpus := filepath.Join(root, "corpus")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(corpus, 0o700); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(rulesDir, "fixture.yar")
	ruleSource := `rule One { meta: family = "alpha" strings: $a = "trigger" condition: $a }
rule Two { meta: score = 7 strings: $a = "trigger" condition: $a }`
	if err := os.WriteFile(rulePath, []byte(ruleSource), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled := filepath.Join(root, "fixture.yac")
	compileFixture(t, rulesDir, compiled)
	if err := os.WriteFile(filepath.Join(corpus, "clean.bin"), []byte("clean"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpus, "multi.bin"), []byte("trigger"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var stderr bytes.Buffer
	args := []string{"-rules", compiled, "-corpus", corpus, "-source-commit", "fixture", "-libyara-version", "test"}
	if code := runMain(args, &output, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got report
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.CorpusFiles != 2 || got.Summary.ZeroMatch != 1 || got.Summary.MultiMatch != 1 || got.Summary.WorstJSON.Path != "multi.bin" || got.RulesCount != 2 {
		t.Fatalf("unexpected measured report: %+v", got)
	}
	for _, record := range got.Records {
		if record.SecondStatus != "hit" {
			t.Fatalf("record did not hit cache: %+v", record)
		}
	}
	outputPath := filepath.Join(root, "report.json")
	if err := run(append(args, "-out", outputPath), io.Discard); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(outputPath); err != nil || info.Size() == 0 {
		t.Fatalf("output file: info=%v err=%v", info, err)
	}
}

func TestRunRejectsMissingMalformedAndEmptyInputs(t *testing.T) {
	if err := run([]string{"-unknown"}, io.Discard); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := run(nil, io.Discard); err == nil {
		t.Fatal("missing arguments accepted")
	}
	root := t.TempDir()
	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	base := []string{"-rules", filepath.Join(root, "missing.yac"), "-corpus", empty, "-source-commit", "fixture", "-libyara-version", "test"}
	if err := run(base, io.Discard); err == nil || !strings.Contains(err.Error(), "rules identity") {
		t.Fatalf("missing rules error=%v", err)
	}
	rulesDir := filepath.Join(root, "rules")
	if err := os.Mkdir(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "fixture.yar"), []byte("rule Noop { condition: false }"), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled := filepath.Join(root, "fixture.yac")
	compileFixture(t, rulesDir, compiled)
	base[1] = compiled
	if err := run(base, io.Discard); err == nil || !strings.Contains(err.Error(), "no regular files") {
		t.Fatalf("empty corpus error=%v", err)
	}
	if err := os.WriteFile(filepath.Join(empty, "sample"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(compiled, []byte("not rules"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(base, io.Discard); err == nil || !strings.Contains(err.Error(), "load rules") {
		t.Fatalf("malformed rules error=%v", err)
	}
	base[1] = filepath.Join(root, "missing.yac")
	base[3] = filepath.Join(root, "missing-corpus")
	if err := run(base, io.Discard); err == nil || !strings.Contains(err.Error(), "rules identity") {
		t.Fatalf("missing rules error=%v", err)
	}
	base[1] = root // a directory opens but cannot be hashed as a rules artifact
	if err := run(base, io.Discard); err == nil || !strings.Contains(err.Error(), "rules identity") {
		t.Fatalf("directory rules error=%v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunReportsCorpusAndOutputFailures(t *testing.T) {
	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules")
	if err := os.Mkdir(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "fixture.yar"), []byte("rule Noop { condition: false }"), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled := filepath.Join(root, "fixture.yac")
	compileFixture(t, rulesDir, compiled)
	args := []string{"-rules", compiled, "-corpus", filepath.Join(root, "missing"), "-source-commit", "fixture", "-libyara-version", "test"}
	if err := run(args, io.Discard); err == nil || !strings.Contains(err.Error(), "corpus manifest") {
		t.Fatalf("missing corpus error=%v", err)
	}
	corpus := filepath.Join(root, "corpus")
	if err := os.Mkdir(corpus, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpus, "clean"), []byte("clean"), 0o600); err != nil {
		t.Fatal(err)
	}
	args[3] = corpus
	originalMeasure := measureCorpus
	measureCorpus = func(http.Handler, string, []string) ([]record, []uncachedRecord, error) {
		return nil, nil, errors.New("measure failed")
	}
	if err := run(args, io.Discard); err == nil || !strings.Contains(err.Error(), "measure failed") {
		t.Fatalf("measurement failure=%v", err)
	}
	measureCorpus = originalMeasure
	t.Cleanup(func() { measureCorpus = originalMeasure })
	if err := run(args, failingWriter{}); err == nil || !strings.Contains(err.Error(), "write report") {
		t.Fatalf("stdout failure=%v", err)
	}
	if err := run(append(args, "-out", root), io.Discard); err == nil || !strings.Contains(err.Error(), "write report") {
		t.Fatalf("file failure=%v", err)
	}
}

func TestEntrypointReturnsSuccessAndFailure(t *testing.T) {
	var stderr bytes.Buffer
	if code := runMain(nil, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "required") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}

	originalArgs, originalExit := os.Args, exitProcess
	originalOutput, originalError := standardOutput, standardError
	t.Cleanup(func() {
		os.Args, exitProcess = originalArgs, originalExit
		standardOutput, standardError = originalOutput, originalError
	})
	os.Args = []string{"cache-distribution"}
	standardOutput, standardError = io.Discard, io.Discard
	gotCode := -1
	exitProcess = func(code int) { gotCode = code }
	main()
	if gotCode != 2 {
		t.Fatalf("main exit=%d", gotCode)
	}
}

func compileFixture(t *testing.T, rulesDir, out string) {
	t.Helper()
	compiler, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer compiler.Destroy()
	for name, value := range map[string]any{"filename": "", "extension": "", "file_type": "", "filepath": "", "filetype": "", "VBA": false, "owner": ""} {
		if err := compiler.DefineVariable(name, value); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(rulesDir, "*.yar"))
	if err != nil || len(files) != 1 {
		t.Fatalf("fixture rules: %v %v", files, err)
	}
	source, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := compiler.AddFile(source, filepath.Base(files[0])); err != nil {
		t.Fatal(err)
	}
	rules, err := compiler.GetRules()
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	if err := rules.Save(out); err != nil {
		t.Fatal(err)
	}
}
