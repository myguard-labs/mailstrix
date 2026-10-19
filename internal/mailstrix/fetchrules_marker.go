package mailstrix

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// rulesMarkersEnv selects whether fetch-rules installs the optional signed
// marker tree published beside compiled.yac: "auto" (default) or "off".
const rulesMarkersEnv = "MAILSTRIX_RULES_MARKERS"

// Bounds for the optional marker tree. The archive bound applies to the signed
// download; the tree bounds apply to what one archive may expand to on disk.
const (
	maxRulesMarkerFieldBytes = 4 << 10
	maxMarkerArchiveBytes    = 1 << 30
	maxMarkerTreeBytes       = 2 << 30
	maxMarkerTreeEntries     = 1 << 17
	maxMarkerArchiveTrailer  = 1 << 20
)

// markerTreeDirs and markerTreeFiles are the only top-level entries a marker
// archive may create. They are exactly the entries loadMarkerArtifact reads
// beside compiled.yac; nothing else in the cache directory can be replaced.
var (
	markerTreeDirs  = []string{"compiler-inputs", "marker-artifact"}
	markerTreeFiles = []string{"libyara.version", "sources.json"}
)

func markerTreeEntries() []string {
	return append(append([]string{}, markerTreeDirs...), markerTreeFiles...)
}

// Marker status values reported in FetchResult.Marker.
const (
	MarkerStatusAbsent    = "absent"    // the manifest carries no marker field
	MarkerStatusDisabled  = "disabled"  // MAILSTRIX_RULES_MARKERS=off
	MarkerStatusSkipped   = "skipped"   // this binary's linked libyara/compiler differ (full-ruleset fallback)
	MarkerStatusRejected  = "rejected"  // invalid field or tree; compiled.yac still installs
	MarkerStatusInstalled = "installed" // tree verified with the loader and installed beside compiled.yac
)

// rulesMarker is the optional signed manifest field describing the marker tree
// archive. Old clients ignore it (non-strict decoding of the signed manifest).
type rulesMarker struct {
	Asset          string `json:"asset"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	LibyaraSHA256  string `json:"libyara_sha256"`
	CompilerSHA256 string `json:"compiler_sha256"`
	MainSHA256     string `json:"main_sha256"`
}

var markerAssetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// parseRulesMarkersMode maps MAILSTRIX_RULES_MARKERS to "off" (true) or "auto"
// (false). Empty selects the default auto; any other value is refused.
func parseRulesMarkersMode(v string) (off bool, err error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto":
		return false, nil
	case "off":
		return true, nil
	}
	return false, fmt.Errorf("%s must be \"auto\" or \"off\", got %q", rulesMarkersEnv, v)
}

func markerHex64(name, v string) (string, error) {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("marker %s must be 64 hex characters", name)
	}
	return strings.ToLower(v), nil
}

// manifestMarker extracts and validates the optional marker field from the
// exact signed manifest bytes. absent reports no field (or JSON null). A
// non-nil error means only the marker part is ignored; the rest of the signed
// manifest was already validated by the caller and stays authoritative.
func manifestMarker(body []byte, checksum string) (marker *rulesMarker, absent bool, err error) {
	var probe struct {
		Marker json.RawMessage `json:"marker"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, false, fmt.Errorf("marker field: %w", err)
	}
	raw := strings.TrimSpace(string(probe.Marker))
	if raw == "" || raw == "null" {
		return nil, true, nil
	}
	if len(raw) > maxRulesMarkerFieldBytes {
		return nil, false, fmt.Errorf("marker field exceeds %d bytes", maxRulesMarkerFieldBytes)
	}
	var m rulesMarker
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, false, fmt.Errorf("marker field: %w", err)
	}
	if !markerAssetName.MatchString(m.Asset) || !strings.HasSuffix(m.Asset, ".tar.gz") {
		return nil, false, fmt.Errorf("marker asset must be a plain *.tar.gz file name")
	}
	if m.Size <= 0 || m.Size > maxMarkerArchiveBytes {
		return nil, false, fmt.Errorf("marker size must be 1..%d", maxMarkerArchiveBytes)
	}
	for _, f := range []struct {
		name string
		v    *string
	}{{"sha256", &m.SHA256}, {"libyara_sha256", &m.LibyaraSHA256}, {"compiler_sha256", &m.CompilerSHA256}, {"main_sha256", &m.MainSHA256}} {
		if *f.v, err = markerHex64(f.name, *f.v); err != nil {
			return nil, false, err
		}
	}
	if !strings.EqualFold(m.MainSHA256, strings.TrimPrefix(checksum, "sha256:")) {
		return nil, false, fmt.Errorf("marker main_sha256 does not match the manifest compiled.yac checksum")
	}
	return &m, false, nil
}

// markerABIMatches reports whether this binary links the exact libyara archive
// and compiler identity the marker tree was built against. Unsupported builds
// carry no identity and always use the full main ruleset.
func markerABIMatches(m *rulesMarker) bool {
	lib, compiler := strings.ToLower(markerRuntimeLibYaraSHA256), strings.ToLower(markerRuntimeCompilerSHA256)
	return len(lib) == 64 && len(compiler) == 64 && m.LibyaraSHA256 == lib && m.CompilerSHA256 == compiler
}

// stageMarkerTree downloads the signed marker archive, checks its size and
// sha256 against the signed field, extracts it into a fresh staging directory
// in cacheDir, and proves it with loadMarkerArtifact against the verified
// bundle before it can be swapped in. The caller removes the returned stage.
func stageMarkerTree(ctx context.Context, hc *http.Client, base, cacheDir, bundle string, m *rulesMarker) (string, error) {
	archive, err := downloadToTemp(ctx, hc, base+"/"+m.Asset, cacheDir, m.Size)
	if err != nil {
		return "", fmt.Errorf("download marker tree: %w", err)
	}
	defer func() { _ = os.Remove(archive) }()
	if err := verifyBundle(archive, RulesManifest{Size: m.Size, Checksum: "sha256:" + m.SHA256}); err != nil {
		return "", fmt.Errorf("verify marker tree: %w", err)
	}
	stage, err := os.MkdirTemp(cacheDir, ".marker-stage-")
	if err != nil {
		return "", err
	}
	if err := extractMarkerTree(ctx, archive, stage); err != nil {
		_ = os.RemoveAll(stage)
		return "", fmt.Errorf("extract marker tree: %w", err)
	}
	if err := verifyStagedMarkerTree(stage, bundle); err != nil {
		_ = os.RemoveAll(stage)
		return "", fmt.Errorf("marker tree does not load: %w", err)
	}
	return stage, nil
}

// verifyStagedMarkerTree runs the unchanged production loader over the staged
// tree with the staged main bundle, exactly as a reload would after the swap.
func verifyStagedMarkerTree(stage, bundle string) error {
	// go-yara returns no rules object with a load error, so nothing leaks here.
	main, identity, err := readRulesSnapshot(bundle)
	if err != nil {
		return err
	}
	defer main.Destroy()
	rules, _, err := loadMarkerArtifact(stage, main, identity)
	if err != nil {
		return err
	}
	rules.Destroy()
	return nil
}

// markerTreeEntryName returns the cleaned slash path of one archive entry, ""
// for the archive root itself. Absolute paths, empty/"."/".." components,
// backslashes, NUL bytes and entries outside the allowed top-level set fail.
func markerTreeEntryName(raw string, dir bool) (string, error) {
	if strings.ContainsAny(raw, "\\\x00") {
		return "", fmt.Errorf("marker archive entry %q has an invalid character", raw)
	}
	if strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("marker archive entry %q is absolute", raw)
	}
	name := strings.TrimPrefix(raw, "./")
	if dir {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || name == "." {
		if !dir {
			return "", fmt.Errorf("marker archive file entry has no name")
		}
		return "", nil
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("marker archive entry %q leaves or obscures the tree", raw)
		}
	}
	top := parts[0]
	for _, d := range markerTreeDirs {
		if top == d && (len(parts) > 1 || dir) {
			return name, nil
		}
	}
	for _, f := range markerTreeFiles {
		if name == f && !dir {
			return name, nil
		}
	}
	return "", fmt.Errorf("marker archive entry %q is outside the marker tree", raw)
}

// extractMarkerTree expands a gzip tar into dest, creating only directories and
// regular files. Links, devices, FIFOs, sparse and global-header entries are
// refused, as are duplicate files and anything beyond the tree bounds. The
// gzip trailer is read so a truncated or corrupt stream cannot pass.
func extractMarkerTree(ctx context.Context, archive, dest string) error {
	f, err := os.Open(archive) // #nosec G304 -- our own verified temp file in the cache dir
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var total int64
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if entries >= maxMarkerTreeEntries {
			return fmt.Errorf("marker archive has more than %d entries", maxMarkerTreeEntries)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			name, err := markerTreeEntryName(hdr.Name, true)
			if err != nil {
				return err
			}
			if name == "" {
				continue
			}
			if err := markerMkdirAll(dest, name); err != nil {
				return err
			}
		case tar.TypeReg:
			name, err := markerTreeEntryName(hdr.Name, false)
			if err != nil {
				return err
			}
			if hdr.Size > maxMarkerTreeBytes-total {
				return fmt.Errorf("marker tree exceeds %d bytes", int64(maxMarkerTreeBytes))
			}
			total += hdr.Size
			if parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(name))); parent != "." {
				if err := markerMkdirAll(dest, parent); err != nil {
					return err
				}
			}
			if err := markerWriteFile(filepath.Join(dest, filepath.FromSlash(name)), tr, hdr.Size); err != nil {
				return err
			}
		default:
			return fmt.Errorf("marker archive entry %q has disallowed type %q", hdr.Name, hdr.Typeflag)
		}
	}
	// End-of-archive blocks may be followed by gzip padding; read the rest of
	// the stream (bounded) so the gzip CRC/size trailer is actually verified.
	n, err := io.Copy(io.Discard, io.LimitReader(gz, maxMarkerArchiveTrailer+1))
	if err != nil {
		return err
	}
	if n > maxMarkerArchiveTrailer {
		return fmt.Errorf("marker archive has more than %d trailing bytes", maxMarkerArchiveTrailer)
	}
	return nil
}

// markerMkdirAll creates name's directories under dest one component at a
// time with Lstat checks, so an existing non-directory is never followed.
func markerMkdirAll(dest, name string) error {
	path := dest
	for _, part := range strings.Split(name, "/") {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("marker archive directory %q collides with a file", name)
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func markerWriteFile(path string, r io.Reader, size int64) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- validated descendant of our private staging dir
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(r, size))
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

// markerTreeRename is the rename used for marker tree swaps; a variable so
// tests can interrupt the swap between individual renames.
var markerTreeRename = os.Rename

// markerTreeSwap moves the live tree aside into the transaction's rollback
// directory and installs a staged tree in its place. Individual renames are
// atomic; any mixed state between them fails loadMarkerArtifact's identity
// checks (the index binds the exact compiled.yac hash), so a reader in that
// window, or after a crash, uses the full main ruleset.
type markerTreeSwap struct {
	cacheDir  string
	aside     string
	moved     []string
	installed []string
}

func newMarkerTreeSwap(cacheDir, rollbackDir string) *markerTreeSwap {
	return &markerTreeSwap{cacheDir: cacheDir, aside: filepath.Join(rollbackDir, "marker-tree")}
}

// retire moves every existing live tree entry aside. Called on every update:
// a tree bound to the previous compiled.yac can never verify against a new one.
func (w *markerTreeSwap) retire() error {
	if err := os.Mkdir(w.aside, 0o700); err != nil {
		return err
	}
	for _, name := range markerTreeEntries() {
		live := filepath.Join(w.cacheDir, name)
		if _, err := os.Lstat(live); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if err := markerTreeRename(live, filepath.Join(w.aside, name)); err != nil {
			return err
		}
		w.moved = append(w.moved, name)
	}
	return nil
}

// install renames each verified staged entry into the cache directory.
func (w *markerTreeSwap) install(stage string) error {
	for _, name := range markerTreeEntries() {
		if err := markerTreeRename(filepath.Join(stage, name), filepath.Join(w.cacheDir, name)); err != nil {
			return err
		}
		w.installed = append(w.installed, name)
	}
	return nil
}

// restore removes newly installed entries and moves the retired tree back.
func (w *markerTreeSwap) restore() error {
	var recovery error
	for _, name := range w.installed {
		recovery = errors.Join(recovery, os.RemoveAll(filepath.Join(w.cacheDir, name)))
	}
	w.installed = nil
	for _, name := range w.moved {
		recovery = errors.Join(recovery, markerTreeRename(filepath.Join(w.aside, name), filepath.Join(w.cacheDir, name)))
	}
	w.moved = nil
	return recovery
}
