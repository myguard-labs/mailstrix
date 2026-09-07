package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
)

const (
	maxManifest = 4 << 20
	maxSample   = 16 << 20
	maxSamples  = 10000
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

type source struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Reference       string `json:"reference"`
	Revision        string `json:"revision"`
	License         string `json:"license"`
	LicenseEvidence string `json:"license_evidence"`
	Redistribution  string `json:"redistribution"`
	Privacy         string `json:"privacy"`
	ReviewRef       string `json:"review_ref"`
}

type symbol struct {
	Namespace string `json:"namespace"`
	Rule      string `json:"rule"`
}

type label struct {
	Symbol   symbol `json:"symbol"`
	Expected string `json:"expected"`
}

// Evidence and review apply to every explicit symbol label. Unlisted symbols
// are unknown, even on benign samples: structural indicators may be legitimate.
type truth struct {
	Class       string  `json:"class"`
	Basis       string  `json:"basis"`
	EvidenceRef string  `json:"evidence_ref"`
	ReviewRef   string  `json:"review_ref"`
	Symbols     []label `json:"symbols"`
}

type sample struct {
	ID        string `json:"id"`
	SourceID  string `json:"source_id"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size_bytes"`
	Locator   string `json:"locator"`
	Partition string `json:"partition"`
	Split     string `json:"split"`
	GroupID   string `json:"group_id"`
	Format    string `json:"format"`
	InputUnit string `json:"input_unit"`
	Truth     truth  `json:"truth"`
}

type manifest struct {
	SchemaVersion int      `json:"schema_version"`
	CorpusID      string   `json:"corpus_id"`
	Revision      int      `json:"revision"`
	Sources       []source `json:"sources"`
	Samples       []sample `json:"samples"`
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// checkJSON rejects duplicate keys before encoding/json can silently replace a
// value. Exact field spelling is checked by round-tripping the typed document.
func checkJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting exceeds 16")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := t.(json.Delim); ok {
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or invalid JSON key")
				}
				seen[name] = true
				if err := checkJSON(d, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := checkJSON(d, depth+1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
	}
	return err
}

func decodeManifest(r io.Reader) (manifest, string, error) {
	var m manifest
	b, err := io.ReadAll(io.LimitReader(r, maxManifest+1))
	if err != nil {
		return m, "", errors.New("cannot read manifest")
	}
	if len(b) > maxManifest {
		return m, "", errors.New("manifest exceeds 4 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if err := checkJSON(d, 0); err != nil {
		return m, "", errors.New("invalid JSON or duplicate keys")
	}
	if _, err := d.Token(); err != io.EOF {
		return m, "", errors.New("trailing JSON data")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, "", errors.New("manifest does not match v1 fields")
	}
	// Maps preserve exact key spelling; typed decoding alone is case-insensitive.
	canonical, err := json.Marshal(m)
	if err != nil {
		return m, "", err
	}
	var supplied, typed any
	if err := json.Unmarshal(b, &supplied); err != nil {
		return m, "", err
	}
	if err := json.Unmarshal(canonical, &typed); err != nil {
		return m, "", err
	}
	suppliedJSON, err := json.Marshal(supplied)
	if err != nil {
		return m, "", err
	}
	typedJSON, err := json.Marshal(typed)
	if err != nil {
		return m, "", err
	}
	if !bytes.Equal(suppliedJSON, typedJSON) {
		return m, "", errors.New("all v1 fields required with exact spelling and types")
	}
	if err := m.validate(); err != nil {
		return m, "", err
	}
	return m, digest(b), nil
}

func (m manifest) validate() error {
	if m.SchemaVersion != 1 || m.Revision < 1 || !identifier.MatchString(m.CorpusID) {
		return errors.New("invalid manifest version or ID")
	}
	if len(m.Samples) == 0 || len(m.Samples) > maxSamples || len(m.Sources) == 0 || len(m.Sources) > maxSamples {
		return errors.New("invalid sample/source count")
	}
	sources := make(map[string]source, len(m.Sources))
	for _, s := range m.Sources {
		if _, ok := sources[s.ID]; ok {
			return errors.New("duplicate source ID")
		}
		if !identifier.MatchString(s.ID) || !slices.Contains([]string{"generated", "external"}, s.Kind) || s.Reference == "" || s.Revision == "" || s.License == "" || s.LicenseEvidence == "" || s.ReviewRef == "" || !slices.Contains([]string{"approved", "local-only", "unknown"}, s.Redistribution) || !slices.Contains([]string{"synthetic", "reviewed-public", "restricted", "unknown"}, s.Privacy) {
			return errors.New("incomplete source provenance")
		}
		sources[s.ID] = s
	}
	ids := make(map[string]bool, len(m.Samples))
	groups := make(map[string]string, len(m.Samples))
	hashes := make(map[string]sample, len(m.Samples))
	for _, s := range m.Samples {
		if ids[s.ID] || !identifier.MatchString(s.ID) || !identifier.MatchString(s.GroupID) {
			return errors.New("invalid or duplicate sample/group ID")
		}
		ids[s.ID] = true
		origin, ok := sources[s.SourceID]
		if !ok {
			return errors.New("unknown source ID")
		}
		h, err := hex.DecodeString(s.SHA256)
		if err != nil || len(h) != sha256.Size || hex.EncodeToString(h) != s.SHA256 || s.Size < 1 || s.Size > maxSample {
			return errors.New("invalid checksum or sample size")
		}
		if !fs.ValidPath(s.Locator) || s.Locator == "." {
			return errors.New("locator must be a relative contained file")
		}
		if !slices.Contains([]string{"mime", "office", "pdf", "html", "image"}, s.Format) || !slices.Contains([]string{"file", "message"}, s.InputUnit) {
			return errors.New("unsupported format or input unit")
		}
		if !slices.Contains([]string{"regression", "calibration", "holdout"}, s.Split) {
			return errors.New("invalid split")
		}
		if prev, ok := groups[s.GroupID]; ok && prev != s.Split {
			return errors.New("group crosses splits")
		}
		groups[s.GroupID] = s.Split
		if !slices.Contains([]string{"synthetic-clean", "synthetic-indicator", "external-clean", "external-threat", "external-unlabelled"}, s.Partition) {
			return errors.New("invalid partition")
		}
		if !slices.Contains([]string{"benign", "malicious", "unknown"}, s.Truth.Class) || !slices.Contains([]string{"construction", "independent", "unlabelled"}, s.Truth.Basis) || s.Truth.EvidenceRef == "" || s.Truth.ReviewRef == "" || s.Truth.Symbols == nil || len(s.Truth.Symbols) > 256 {
			return errors.New("incomplete ground truth")
		}
		synthetic := s.Partition == "synthetic-clean" || s.Partition == "synthetic-indicator"
		if synthetic && (origin.Kind != "generated" || origin.Privacy != "synthetic" || origin.Redistribution != "approved" || s.Truth.Class != "benign" || s.Truth.Basis != "construction") {
			return errors.New("synthetic provenance/label mismatch")
		}
		if !synthetic && origin.Kind != "external" {
			return errors.New("external partition requires external source")
		}
		if s.Partition == "external-clean" && s.Truth.Class != "benign" || s.Partition == "external-threat" && s.Truth.Class != "malicious" || s.Partition == "external-unlabelled" && s.Truth.Class != "unknown" {
			return errors.New("partition/truth mismatch")
		}
		if !synthetic && s.Truth.Class != "unknown" && s.Truth.Basis != "independent" {
			return errors.New("external labels require independent evidence")
		}
		seen := map[symbol]bool{}
		for _, l := range s.Truth.Symbols {
			if seen[l.Symbol] || !identifier.MatchString(l.Symbol.Rule) || (l.Symbol.Namespace != "" && !identifier.MatchString(l.Symbol.Namespace)) || !slices.Contains([]string{"present", "absent"}, l.Expected) {
				return errors.New("invalid or duplicate symbol label")
			}
			seen[l.Symbol] = true
		}
		if prior, ok := hashes[s.SHA256]; ok {
			// Identical bytes must have identical evaluation metadata. Aliases may
			// differ only in ID, locator and provenance, never ground truth.
			a, b := prior, s
			a.ID, a.Locator, a.SourceID = "", "", ""
			b.ID, b.Locator, b.SourceID = "", "", ""
			x, err := json.Marshal(a)
			if err != nil {
				return err
			}
			y, err := json.Marshal(b)
			if err != nil {
				return err
			}
			if !bytes.Equal(x, y) {
				return errors.New("duplicate checksum has conflicting metadata or labels")
			}
		}
		hashes[s.SHA256] = s
	}
	return nil
}

func readSample(root *os.Root, s sample) ([]byte, error) {
	// Corpus files must be stable regular files, not devices, FIFOs or symlinks.
	// Root.Open still enforces containment if the caller changes a directory.
	info, err := root.Lstat(s.Locator)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("sample is not an available regular file")
	}
	f, err := root.Open(s.Locator)
	if err != nil {
		return nil, errors.New("sample unavailable or outside corpus root")
	}
	// This read-only handle has no buffered writes to lose on close.
	defer func() { _ = f.Close() }()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("sample is not a regular file")
	}
	if info.Size() != s.Size {
		return nil, errors.New("sample size mismatch")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSample+1))
	if err != nil {
		return nil, errors.New("sample read failed")
	}
	if int64(len(b)) != s.Size || digest(b) != s.SHA256 {
		return nil, errors.New("sample checksum mismatch")
	}
	return b, nil
}

func validateFiles(root *os.Root, m manifest) error {
	for i, s := range m.Samples {
		if _, err := readSample(root, s); err != nil {
			return fmt.Errorf("sample %d: %w", i+1, err)
		}
	}
	return nil
}
