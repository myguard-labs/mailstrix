// Command cache-distribution measures the complete verdict values retained by
// Mailstrix's in-process cache. It is an offline CI/benchmark helper: inputs and
// the compiled rule artifact remain outside the repository.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unsafe"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

type record struct {
	Path                     string     `json:"path"`
	SHA256                   string     `json:"sha256"`
	InputBytes               int        `json:"input_bytes"`
	MatchCount               int        `json:"match_count"`
	MatchesJSONBytes         int        `json:"matches_json_bytes"`
	MetaPairs                int        `json:"meta_pairs"`
	MetaKeyValueBytes        int        `json:"meta_key_value_bytes"`
	ModeledGoValueLowerBound int        `json:"modeled_go_value_lower_bound_bytes"`
	FirstStatus              string     `json:"first_cache_status"`
	SecondStatus             string     `json:"second_cache_status"`
	Matches                  []ms.Match `json:"matches"`
}

type quantiles struct {
	Min int `json:"min"`
	P50 int `json:"p50"`
	P90 int `json:"p90"`
	P95 int `json:"p95"`
	P99 int `json:"p99"`
	Max int `json:"max"`
}

type summary struct {
	Records            int            `json:"records"`
	ZeroMatch          int            `json:"zero_match_records"`
	OneMatch           int            `json:"one_match_records"`
	MultiMatch         int            `json:"multi_match_records"`
	WithMeta           int            `json:"records_with_meta"`
	MatchCount         quantiles      `json:"match_count"`
	MatchesJSON        quantiles      `json:"matches_json_bytes"`
	MetaPairs          quantiles      `json:"meta_pairs"`
	MetaBytes          quantiles      `json:"meta_key_value_bytes"`
	ModeledGoLower     quantiles      `json:"modeled_go_value_lower_bound_bytes"`
	WorstJSON          record         `json:"worst_matches_json_record"`
	WorstModeledGo     record         `json:"worst_modeled_go_lower_bound_record"`
	ObservedNamespaces map[string]int `json:"observed_namespace_match_counts"`
}

type uncachedRecord struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	InputBytes int    `json:"input_bytes"`
	Reason     string `json:"reason"`
}

type report struct {
	Schema               string            `json:"schema"`
	CreatedUTC           string            `json:"created_utc"`
	SourceCommit         string            `json:"source_commit"`
	RulesPath            string            `json:"rules_path"`
	RulesSHA256          string            `json:"rules_sha256"`
	RulesBytes           int64             `json:"rules_bytes"`
	RulesCount           int64             `json:"rules_count"`
	RulesFingerprint     string            `json:"rules_fingerprint"`
	LibyaraVersion       string            `json:"libyara_version"`
	Runtime              string            `json:"go_runtime"`
	CorpusRoot           string            `json:"corpus_root"`
	CorpusManifestSHA256 string            `json:"corpus_manifest_sha256"`
	CorpusFiles          int               `json:"corpus_files"`
	CorpusBytes          int64             `json:"corpus_bytes"`
	ScanExternals        map[string]string `json:"scan_externals"`
	Definitions          map[string]string `json:"definitions"`
	Summary              summary           `json:"summary"`
	Records              []record          `json:"records"`
	Uncached             []uncachedRecord  `json:"uncached_records"`
}

type scanResponse struct {
	Matches  []ms.Match `json:"matches"`
	Degraded string     `json:"degraded,omitempty"`
}

var (
	exitProcess                  = os.Exit
	standardOutput     io.Writer = os.Stdout
	standardError      io.Writer = os.Stderr
	walkCorpus                   = filepath.WalkDir
	corpusEntryInfo              = func(entry os.DirEntry) (os.FileInfo, error) { return entry.Info() }
	hashCorpusFile               = hashFile
	relativeCorpusPath           = filepath.Rel
	measureCorpus                = measurePaths
)

func main() { exitProcess(runMain(os.Args[1:], standardOutput, standardError)) }

func runMain(args []string, stdout, stderr io.Writer) int {
	if err := run(args, stdout); err != nil {
		fmt.Fprintln(stderr, "cache-distribution:", err)
		return 2
	}
	return 0
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("cache-distribution", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rules := fs.String("rules", "", "identity-bound compiled .yac")
	corpus := fs.String("corpus", "", "corpus directory scanned recursively")
	source := fs.String("source-commit", "", "source commit being measured")
	libyara := fs.String("libyara-version", "", "linked libyara version")
	out := fs.String("out", "", "output JSON path (stdout when empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rules == "" || *corpus == "" || *source == "" || *libyara == "" {
		return fmt.Errorf("-rules, -corpus, -source-commit, and -libyara-version are required")
	}

	rulesHash, rulesBytes, err := hashFile(*rules)
	if err != nil {
		return fmt.Errorf("rules identity: %w", err)
	}
	paths, corpusBytes, manifestHash, err := corpusManifest(*corpus)
	if err != nil {
		return fmt.Errorf("corpus manifest: %w", err)
	}
	if len(paths) == 0 {
		return fmt.Errorf("corpus has no regular files")
	}

	cfg := &ms.Config{
		RulesPath: *rules, ScanTimeout: 2 * time.Minute, MaxBody: 128 << 20,
		MaxConcurrent: 1, MaxInflight: 2, CacheTTL: time.Hour,
		CacheSize: len(paths) + 1, Effort: 10, EffortMax: 10,
	}
	cfg.Finalize()
	scanner, err := ms.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	defer scanner.Close()
	server := ms.NewServer(cfg, scanner)

	records, uncached, err := measureCorpus(server, *corpus, paths)
	if err != nil {
		return err
	}

	r := report{
		Schema: "mailstrix-cache-distribution-v1", CreatedUTC: time.Now().UTC().Format(time.RFC3339),
		SourceCommit: *source, RulesPath: *rules, RulesSHA256: rulesHash, RulesBytes: rulesBytes,
		RulesCount: scanner.RuleCount(), RulesFingerprint: scanner.Fingerprint(),
		LibyaraVersion: *libyara, Runtime: runtime.Version(), CorpusRoot: *corpus,
		CorpusManifestSHA256: manifestHash, CorpusFiles: len(paths), CorpusBytes: corpusBytes,
		ScanExternals: map[string]string{"filename": "relative basename (base64 HTTP header)", "extension": "derived from filename", "file_type": "derived from filename", "VBA": "false on raw channel; production extraction controls subchannels", "effort": "10, capped at 10", "feeds": "disabled (no keys/endpoints configured)"},
		Definitions: map[string]string{
			"matches_json_bytes":                 "exact len(json.Marshal(matches)) for the complete HTTP-decoded []Match value; nil scanner matches are normalized to [] by the HTTP response, while a direct Redis cache encoding can be null, so this is not an unconditional Redis-value size claim",
			"meta_key_value_bytes":               "sum of byte lengths of every Meta key and value; excludes Go map buckets and allocator rounding",
			"modeled_go_value_lower_bound_bytes": "model over the HTTP-decoded []Match: cap(matches)*sizeof(Match) + all Rule/Namespace/tag/Meta string bytes + cap(Tags)*sizeof(string); it does not observe the cache backing capacities or sharing and excludes Meta map buckets, allocator rounding, cache key, entry/list/map index objects, and shared rule storage, so it is neither exact retained heap nor an allocation measurement",
			"allocation_and_rss":                 "not measured; no allocation or RSS claim is made",
			"cache_binding":                      "each record is the first complete HTTP /scan verdict followed by a verified X-MAILSTRIX-Cache=hit response with byte-identical matches",
		},
		Summary: summarize(records), Records: records, Uncached: uncached,
	}
	// report contains only JSON-native values, so MarshalIndent cannot encounter
	// unsupported types or cycles.
	encoded, _ := json.MarshalIndent(r, "", "  ")
	encoded = append(encoded, '\n')
	if *out == "" {
		_, err = stdout.Write(encoded)
	} else {
		err = os.WriteFile(*out, encoded, 0o600)
	}
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func measurePaths(server http.Handler, corpus string, paths []string) ([]record, []uncachedRecord, error) {
	records := make([]record, 0, len(paths))
	uncached := make([]uncachedRecord, 0)
	for _, path := range paths {
		// The operator explicitly supplies the offline corpus root; every path was
		// enumerated beneath it by corpusManifest immediately before this read.
		body, err := os.ReadFile(path) // #nosec G304 -- intentional operator-selected corpus
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
		first, firstStatus, err := request(server, body, filepath.Base(path))
		if err != nil {
			uncached = append(uncached, makeUncachedRecord(strings.TrimPrefix(path, filepath.Clean(corpus)+string(os.PathSeparator)), body, "first scan: "+err.Error()))
			continue
		}
		if first.Degraded != "" {
			uncached = append(uncached, makeUncachedRecord(strings.TrimPrefix(path, filepath.Clean(corpus)+string(os.PathSeparator)), body, "first scan degraded: "+first.Degraded))
			continue
		}
		second, secondStatus, err := request(server, body, filepath.Base(path))
		if err != nil {
			uncached = append(uncached, makeUncachedRecord(strings.TrimPrefix(path, filepath.Clean(corpus)+string(os.PathSeparator)), body, "second scan: "+err.Error()))
			continue
		}
		if second.Degraded != "" || secondStatus != "hit" {
			uncached = append(uncached, makeUncachedRecord(strings.TrimPrefix(path, filepath.Clean(corpus)+string(os.PathSeparator)), body, fmt.Sprintf("second scan status=%q degraded=%q", secondStatus, second.Degraded)))
			continue
		}
		firstJSON, _ := json.Marshal(first.Matches)
		secondJSON, _ := json.Marshal(second.Matches)
		if !bytes.Equal(firstJSON, secondJSON) {
			uncached = append(uncached, makeUncachedRecord(strings.TrimPrefix(path, filepath.Clean(corpus)+string(os.PathSeparator)), body, "cache hit changed matches"))
			continue
		}
		records = append(records, makeRecord(strings.TrimPrefix(path, filepath.Clean(corpus)+string(os.PathSeparator)), body, first.Matches, firstStatus, secondStatus))
	}
	return records, uncached, nil
}

func request(server http.Handler, body []byte, name string) (scanResponse, string, error) {
	req := httptest.NewRequest("POST", "/scan", bytes.NewReader(body))
	req.Header.Set("Content-Length", fmt.Sprint(len(body)))
	req.Header.Set("X-MAILSTRIX-Filename", base64.StdEncoding.EncodeToString([]byte(name)))
	req.Header.Set("X-MAILSTRIX-Effort", "10")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != 200 {
		return scanResponse{}, "", fmt.Errorf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var response scanResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		return response, "", err
	}
	return response, w.Header().Get("X-MAILSTRIX-Cache"), nil
}

func makeRecord(path string, body []byte, matches []ms.Match, first, second string) record {
	serialized, _ := json.Marshal(matches)
	r := record{Path: filepath.ToSlash(path), InputBytes: len(body), MatchCount: len(matches), MatchesJSONBytes: len(serialized), FirstStatus: first, SecondStatus: second, Matches: matches}
	h := sha256.Sum256(body)
	r.SHA256 = hex.EncodeToString(h[:])
	r.ModeledGoValueLowerBound = cap(matches) * int(unsafe.Sizeof(ms.Match{}))
	for _, m := range matches {
		r.ModeledGoValueLowerBound += len(m.Rule) + len(m.Namespace) + cap(m.Tags)*int(unsafe.Sizeof(""))
		for _, tag := range m.Tags {
			r.ModeledGoValueLowerBound += len(tag)
		}
		for key, value := range m.Meta {
			r.MetaPairs++
			r.MetaKeyValueBytes += len(key) + len(value)
			r.ModeledGoValueLowerBound += len(key) + len(value)
		}
	}
	return r
}

func makeUncachedRecord(path string, body []byte, reason string) uncachedRecord {
	h := sha256.Sum256(body)
	return uncachedRecord{Path: filepath.ToSlash(path), SHA256: hex.EncodeToString(h[:]), InputBytes: len(body), Reason: reason}
}

func summarize(records []record) summary {
	s := summary{Records: len(records), ObservedNamespaces: make(map[string]int)}
	counts, jsonSizes, pairs, metaBytes, retained := make([]int, 0, len(records)), make([]int, 0, len(records)), make([]int, 0, len(records)), make([]int, 0, len(records)), make([]int, 0, len(records))
	for i, r := range records {
		switch r.MatchCount {
		case 0:
			s.ZeroMatch++
		case 1:
			s.OneMatch++
		default:
			s.MultiMatch++
		}
		if r.MetaPairs > 0 {
			s.WithMeta++
		}
		for _, match := range r.Matches {
			s.ObservedNamespaces[match.Namespace]++
		}
		counts = append(counts, r.MatchCount)
		jsonSizes = append(jsonSizes, r.MatchesJSONBytes)
		pairs = append(pairs, r.MetaPairs)
		metaBytes = append(metaBytes, r.MetaKeyValueBytes)
		retained = append(retained, r.ModeledGoValueLowerBound)
		if i == 0 || r.MatchesJSONBytes > s.WorstJSON.MatchesJSONBytes || (r.MatchesJSONBytes == s.WorstJSON.MatchesJSONBytes && r.Path < s.WorstJSON.Path) {
			s.WorstJSON = r
		}
		if i == 0 || r.ModeledGoValueLowerBound > s.WorstModeledGo.ModeledGoValueLowerBound || (r.ModeledGoValueLowerBound == s.WorstModeledGo.ModeledGoValueLowerBound && r.Path < s.WorstModeledGo.Path) {
			s.WorstModeledGo = r
		}
	}
	s.MatchCount = distribution(counts)
	s.MatchesJSON = distribution(jsonSizes)
	s.MetaPairs = distribution(pairs)
	s.MetaBytes = distribution(metaBytes)
	s.ModeledGoLower = distribution(retained)
	return s
}

func distribution(values []int) quantiles {
	if len(values) == 0 {
		return quantiles{}
	}
	sort.Ints(values)
	at := func(p int) int { return values[(p*len(values)+99)/100-1] }
	return quantiles{Min: values[0], P50: at(50), P90: at(90), P95: at(95), P99: at(99), Max: values[len(values)-1]}
}

func corpusManifest(root string) ([]string, int64, string, error) {
	var paths []string
	var bytesTotal int64
	err := walkCorpus(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := corpusEntryInfo(entry)
		if err != nil {
			return err
		}
		paths = append(paths, path)
		bytesTotal += info.Size()
		return nil
	})
	if err != nil {
		return nil, 0, "", err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		digest, size, err := hashCorpusFile(path)
		if err != nil {
			return nil, 0, "", err
		}
		rel, err := relativeCorpusPath(root, path)
		if err != nil {
			return nil, 0, "", err
		}
		fmt.Fprintf(h, "%s  %d  %s\n", digest, size, filepath.ToSlash(rel))
	}
	return paths, bytesTotal, hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(path string) (string, int64, error) {
	// Rules and corpus artifacts are explicit CLI inputs to this offline tool.
	f, err := os.Open(path) // #nosec G304 -- intentional operator-selected artifact
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return hashReader(f)
}

func hashReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
