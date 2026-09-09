package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// cmdFetchRules downloads an updated compiled rule bundle into the cache, driven
// by the published manifest: it fetches the manifest first and updates only when
// the remote version is newer and the libyara version matches. It verifies the
// download (sha256) and swaps atomically, keeping one backup. It is the
// counterpart to generate-rules.sh and the primary rule-update path for both
// Docker and non-Docker users (no local yarac / compile).
//
// Exit codes: 0 = up to date or updated successfully; 2 = error (kept the current
// bundle). A `serve`-time interval fetch reuses internal/mailstrix.FetchRules.
func cmdFetchRules(args []string) int {
	cfg := mailstrix.LoadConfig()

	fs := flag.NewFlagSet("fetch-rules", flag.ContinueOnError)
	url := fs.String("url", firstNonEmpty(cfg.RulesURL, mailstrix.DefaultRulesURL), "base URL holding compiled.yac + its manifest (MAILSTRIX_RULES_URL)")
	cacheDir := fs.String("cache-dir", firstNonEmpty(cfg.CacheDir, "/var/cache/mailstrix"), "cache dir for the live bundle (MAILSTRIX_CACHE_DIR)")
	timeout := fs.Duration("timeout", 60*time.Second, "overall HTTP timeout")
	verifyOnly := fs.Bool("verify-only", false, "verify into a fresh temporary cache and remove it; never touch the configured cache")
	expectedVersion := fs.Int("expected-version", 0, "with -verify-only, require this published version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *expectedVersion < 0 || (*expectedVersion > 0 && !*verifyOnly) {
		fmt.Fprintln(os.Stderr, "expected-version requires verify-only and a positive version")
		return 2
	}
	if *verifyOnly {
		dir, err := os.MkdirTemp("", "strixd-verify-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		defer func() { _ = os.RemoveAll(dir) }()
		*cacheDir = dir
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	// Redirects ARE followed (a GitHub release-asset URL legitimately 30x's to the
	// object store, so a blanket reject would break the default URL), but the chain
	// is bounded. These requests carry NO auth/secret header — the bundle is a
	// public asset — so there is nothing for a redirect to leak; the only guard
	// needed is a hop cap against a redirect loop.
	hc := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	res, err := mailstrix.FetchRules(ctx, *url, *cacheDir, libyaraVersion, hc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strixd fetch-rules:", err)
		return 2
	}
	if *expectedVersion > 0 && res.NewVersion != *expectedVersion {
		fmt.Fprintf(os.Stderr, "verify-rules: published version %d, expected %d\n", res.NewVersion, *expectedVersion)
		return 2
	}
	if *verifyOnly {
		if !res.Updated {
			fmt.Fprintln(os.Stderr, "verify-rules: no bundle was staged and load-validated:", res.Reason)
			return 2
		}
		m, ok, err := mailstrix.LoadManifest(*cacheDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify-rules: read verified manifest:", err)
			return 2
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "verify-rules: verified manifest missing")
			return 2
		}
		fmt.Printf("verify-rules: version=%d libyara=%s size=%d checksum=%s loadable=true\n", m.Version, m.Libyara, m.Size, m.Checksum)
		return 0
	}
	if res.Updated {
		fmt.Printf("fetch-rules: %s — restart or SIGHUP strixd to load the new bundle\n", res.Reason)
	} else {
		fmt.Printf("fetch-rules: %s\n", res.Reason)
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
