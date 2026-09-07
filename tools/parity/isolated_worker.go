package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"runtime"
	"slices"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

const (
	isolatedOutputLimit = 1 << 20
	isolatedHeaderLimit = 4096
	isolatedSymbolLimit = 4096
	isolatedRulesDir    = "/usr/share/mailstrix/parity-rules"
	isolatedScanBudget  = 8 * time.Second
)

// Set only by the optional image build; ordinary host builds cannot claim the
// image's libyara identity. Checksums identify bytes, not source attestation.
var isolatedLibyaraVersion = "unknown"

type isolatedRequest struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Format    string `json:"format"`
	InputUnit string `json:"input_unit"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

type isolatedIdentity struct {
	BinarySHA256           string `json:"binary_sha256"`
	LibyaraVersion         string `json:"libyara_version"`
	GoVersion              string `json:"go_version"`
	Platform               string `json:"platform"`
	RulesFingerprintSHA256 string `json:"rules_fingerprint_sha256"`
}

type isolatedResponse struct {
	Version  int              `json:"version"`
	Status   string           `json:"status"`
	Identity isolatedIdentity `json:"identity"`
	Symbols  []symbol         `json:"symbols"`
}

// Require one complete, exact typed object: duplicate keys, unknown or missing
// fields, case-folded keys, null lists and trailing messages are not extensions.
func isolatedJSON(b []byte, out any) error {
	if len(b) == 0 || len(b) > isolatedOutputLimit {
		return errors.New("invalid isolated message size")
	}
	if err := strictComparatorJSON(b, out); err != nil {
		return err
	}
	canonical, err := json.Marshal(out)
	if err != nil {
		return err
	}
	var supplied, typed any
	if err := json.Unmarshal(b, &supplied); err != nil {
		return err
	}
	if err := json.Unmarshal(canonical, &typed); err != nil {
		return err
	}
	if !reflect.DeepEqual(supplied, typed) {
		return errors.New("isolated fields do not match protocol")
	}
	return nil
}

func sha256Text(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

func (r isolatedRequest) valid() bool {
	if r.Version != 1 {
		return false
	}
	if r.Operation == "identity" {
		return r.Format == "" && r.InputUnit == "" && r.Size == 0 && r.SHA256 == ""
	}
	return r.Operation == "scan" && r.Size > 0 && r.Size <= maxSample && sha256Text(r.SHA256) &&
		slices.Contains([]string{"mime", "office", "pdf", "html", "image"}, r.Format) &&
		slices.Contains([]string{"file", "message"}, r.InputUnit)
}

// A big-endian uint32 header length precedes exact JSON and exact sample bytes.
// No caller paths, sample names, labels or secrets cross the worker boundary.
func encodeIsolatedRequest(r isolatedRequest, data []byte) ([]byte, error) {
	if !r.valid() || r.Size != int64(len(data)) || r.Operation == "scan" && digest(data) != r.SHA256 {
		return nil, errors.New("invalid isolated request")
	}
	header, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	headerSize := len(header)
	if headerSize > isolatedHeaderLimit {
		return nil, errors.New("isolated request header exceeds limit")
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, uint32(headerSize)); err != nil {
		return nil, err
	}
	b.Write(header)
	b.Write(data)
	return b.Bytes(), nil
}

func decodeIsolatedRequest(in io.Reader) (isolatedRequest, []byte, error) {
	var r isolatedRequest
	var n uint32
	if err := binary.Read(in, binary.BigEndian, &n); err != nil {
		return r, nil, err
	}
	if n == 0 || n > isolatedHeaderLimit {
		return r, nil, errors.New("invalid frame size")
	}
	header := make([]byte, n)
	if _, err := io.ReadFull(in, header); err != nil {
		return r, nil, err
	}
	if err := isolatedJSON(header, &r); err != nil {
		return r, nil, err
	}
	if !r.valid() {
		return r, nil, errors.New("invalid request fields")
	}
	data, err := io.ReadAll(io.LimitReader(in, r.Size+1))
	if err != nil || int64(len(data)) != r.Size {
		return r, nil, errors.New("invalid payload length")
	}
	if r.Operation == "scan" && digest(data) != r.SHA256 {
		return r, nil, errors.New("payload checksum mismatch")
	}
	return r, data, nil
}

func validIsolatedIdentity(i isolatedIdentity) bool {
	return sha256Text(i.BinarySHA256) && sha256Text(i.RulesFingerprintSHA256) &&
		i.LibyaraVersion == "4.5.2" && i.Platform == "linux/amd64" &&
		len(i.GoVersion) < 64 && identifier.MatchString(i.GoVersion)
}

func decodeIsolatedResponse(b []byte) (isolatedResponse, error) {
	var r isolatedResponse
	if err := isolatedJSON(b, &r); err != nil {
		return r, err
	}
	if r.Version != 1 || !validIsolatedIdentity(r.Identity) || r.Symbols == nil || len(r.Symbols) > isolatedSymbolLimit ||
		!slices.Contains([]string{"ok", "error", "timeout", "indeterminate"}, r.Status) || r.Status != "ok" && len(r.Symbols) != 0 {
		return r, errors.New("invalid isolated response")
	}
	seen := make(map[symbol]bool, len(r.Symbols))
	for _, s := range r.Symbols {
		if !identifier.MatchString(s.Namespace) || !identifier.MatchString(s.Rule) || seen[s] {
			return r, errors.New("invalid isolated symbol")
		}
		seen[s] = true
	}
	return r, nil
}

func isolatedWorker(in io.Reader, out io.Writer) int {
	r, data, err := decodeIsolatedRequest(in)
	if err != nil {
		return 2
	}
	// Fixed configuration: no feed, cache, password guessing or environment loader.
	cfg := &mailstrix.Config{RulesDir: isolatedRulesDir, ScanTimeout: isolatedScanBudget, EffortMax: scanEffort}
	scanner, diagnostic, err := newParityScanner(cfg)
	if err != nil {
		return 2
	}
	defer scanner.Close()
	if diagnostic.Load() {
		return 2
	}
	// /proc/self/exe is the actual running image binary, not the host executable.
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return 2
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return 2
	}
	i := isolatedIdentity{hex.EncodeToString(h.Sum(nil)), isolatedLibyaraVersion, runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH, digest([]byte(scanner.Fingerprint()))}
	if !validIsolatedIdentity(i) {
		return 2
	}
	o := observation{Status: "ok", Matches: []symbol{}}
	if r.Operation == "scan" {
		started := time.Now()
		o = observe(scanner, data, r.Format)
		if time.Since(started) >= cfg.ScanTimeout {
			o = observation{Status: "timeout"}
		} else if o.Status == "ok" && diagnostic.Load() {
			o = observation{Status: "indeterminate"}
		}
	}
	// Match multiplicity and ordering are implementation details, not the wire contract.
	slices.SortFunc(o.Matches, func(a, b symbol) int {
		if a.Namespace < b.Namespace {
			return -1
		}
		if a.Namespace > b.Namespace {
			return 1
		}
		if a.Rule < b.Rule {
			return -1
		}
		if a.Rule > b.Rule {
			return 1
		}
		return 0
	})
	o.Matches = slices.Compact(o.Matches)
	if o.Matches == nil {
		o.Matches = []symbol{}
	}
	response := isolatedResponse{1, o.Status, i, o.Matches}
	b, err := json.Marshal(response)
	if err != nil {
		return 2
	}
	if _, err := decodeIsolatedResponse(b); err != nil {
		return 2
	}
	if _, err := out.Write(b); err != nil {
		return 2
	}
	return 0
}
