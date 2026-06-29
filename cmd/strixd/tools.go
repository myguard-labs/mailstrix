package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/eilandert/mailstrix/internal/extract"
	"github.com/eilandert/mailstrix/internal/mailstrix"
)

// cmdCheckRules compiles the configured rule set and reports the result without
// starting the server: a CI / pre-deploy gate. Exit 0 = rules compiled and at
// least one rule loaded; exit 1 = nothing compilable (NewScanner's error). The
// compile itself logs how many files were skipped as unparseable, so a partially
// broken set is visible but not fatal — matching the running server's posture.
func cmdCheckRules(args []string) int {
	cfg := mailstrix.LoadConfig()
	cfg.Version = version

	fs := flag.NewFlagSet("check-rules", flag.ContinueOnError)
	fs.StringVar(&cfg.RulesDir, "rules-dir", cfg.RulesDir, "dir of *.yar/*.yara to compile (MAILSTRIX_RULES_DIR)")
	fs.StringVar(&cfg.RulesPath, "rules", cfg.RulesPath, "precompiled .yac bundle, wins over -rules-dir (MAILSTRIX_RULES)")
	fs.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "writable dir for the live rule bundle (MAILSTRIX_CACHE_DIR)")
	fs.StringVar(&cfg.SeedRules, "seed-rules", cfg.SeedRules, "baked read-only .yac used to (re)seed the cache (MAILSTRIX_SEED_RULES)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	logf := func(format string, a ...any) { log.Printf("[mailstrix] "+format, a...) }

	// Mirror cmdServe: seed the rule cache from MAILSTRIX_SEED_RULES when the cache
	// is missing/unreadable, so `strixd check-rules` works in the Docker final
	// image without extra operator env. No-op when CacheDir is empty.
	if err := mailstrix.EnsureCachedRules(cfg, logf); err != nil {
		logf("rules cache unavailable, falling back to baked rules: %v", err)
	}

	scanner, err := mailstrix.NewScanner(cfg, logf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-rules: FAILED: %v\n", err)
		return 1
	}
	fmt.Printf("check-rules: OK — %d rules loaded (fingerprint %s)\n",
		scanner.RuleCount(), scanner.Fingerprint())
	return 0
}

// cmdExtract runs the container-extraction layer over a file (or stdin) and
// reports what it carved — the container type recognised and each member stream's
// size and SHA-256 — WITHOUT scanning against rules. It is a debug aid for the
// extractor: when a dropper isn't matched, this shows whether the member bytes
// were surfaced at all. With -out <dir> the carved streams are written to disk
// for manual inspection. Exit 0 if anything was carved, 1 if not, 2 on a usage /
// read error.
func cmdExtract(args []string) int {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	outDir := fs.String("out", "", "write each carved stream to this directory as <NNN>.bin")
	timeout := fs.Duration("timeout", 10*time.Second, "extraction deadline")
	maxBody := fs.Int64("max-body", 64<<20, "max bytes read from the input")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// A non-positive -max-body would turn the io.LimitReader below into an
	// unbounded read; restore a sane cap.
	if *maxBody <= 0 {
		*maxBody = 64 << 20
	}

	path := "-"
	if a := fs.Args(); len(a) > 1 {
		fmt.Fprintln(os.Stderr, "extract: at most one path (or stdin)")
		return 2
	} else if len(a) == 1 {
		path = a[0]
	}

	var (
		buf []byte
		err error
	)
	if path == "-" {
		buf, err = readExtractInput(os.Stdin, *maxBody)
	} else {
		var f *os.File
		// #nosec G304 -- extract intentionally reads an operator-supplied path
		if f, err = os.Open(path); err == nil {
			defer f.Close()
			buf, err = readExtractInput(f, *maxBody)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract: %v\n", err)
		return 2
	}

	res := extract.Extract(buf, time.Now().Add(*timeout))

	fmt.Printf("input:      %s (%d bytes)\n", path, len(buf))
	fmt.Printf("container:  %s\n", containerKind(res))
	if res.Encrypted {
		fmt.Println("encrypted:  yes (not decrypted)")
	}
	if res.Failed {
		fmt.Printf("parse:      failed%s\n", panickedNote(res))
	}
	fmt.Printf("streams:    %d carved\n", len(res.Streams))

	if *outDir != "" && len(res.Streams) > 0 {
		if err := os.MkdirAll(*outDir, 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "extract: -out: %v\n", err)
			return 2
		}
	}
	for i, s := range res.Streams {
		sum := sha256.Sum256(s)
		fmt.Printf("  [%d] %8d bytes  sha256=%s\n", i, len(s), hex.EncodeToString(sum[:]))
		if *outDir != "" {
			name := filepath.Join(*outDir, fmt.Sprintf("%03d.bin", i))
			// 0600: a carved stream may be a live malware sample; keep it owner-only.
			if err := os.WriteFile(name, s, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "extract: write %s: %v\n", name, err)
				return 2
			}
		}
	}

	// Out-of-band PURE markers (encrypted-archive, OLEID indicators, …) live in
	// res.Markers, not res.Streams. Surface them too so a marker-only detection
	// (e.g. a header-encrypted archive, which carves no content) is visible when
	// debugging rather than reported as "0 carved / nothing found".
	if len(res.Markers) > 0 {
		fmt.Printf("markers:    %d\n", len(res.Markers))
		for i, m := range res.Markers {
			fmt.Printf("  [m%d] %s\n", i, string(m))
		}
	}

	if len(res.Streams) == 0 && len(res.Markers) == 0 {
		return 1
	}
	return 0
}

func readExtractInput(r io.Reader, maxBody int64) ([]byte, error) {
	limit := maxBody + 1
	if limit < maxBody {
		limit = maxBody
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxBody {
		return nil, fmt.Errorf("oversized: exceeds max-body %d bytes; not extracted", maxBody)
	}
	return buf, nil
}

// containerKind names the container type the extractor recognised, for the
// extract report. The flags are mutually exclusive in practice (one dispatch
// branch sets one), so the first set flag wins; "none" means the input wasn't a
// recognised container (it may still have yielded a decoded script block).
func containerKind(r extract.Result) string {
	switch {
	case r.IsMSI:
		return "ole2/msi"
	case r.IsMSG:
		return "ole2/msg (outlook)"
	case r.IsOLEPackage:
		return "ole2 + ole-package"
	case r.IsRTF:
		return "rtf"
	case r.IsSLK:
		return "sylk (.slk)"
	case r.IsPDF:
		return "pdf"
	case r.IsLNK:
		return "lnk (shell link)"
	case r.IsOneNote:
		return "onenote"
	case r.IsArchive:
		return "archive (zip/gz/7z/rar/tar)"
	case r.EncodedScript:
		return "encoded script (vbe/jse)"
	case r.IsDoc:
		return "ole2/ooxml document"
	default:
		return "none"
	}
}

// panickedNote annotates a failed parse with whether it was a recovered panic.
func panickedNote(r extract.Result) string {
	if r.Panicked {
		return " (recovered panic)"
	}
	return ""
}
