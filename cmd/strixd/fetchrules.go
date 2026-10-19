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
	allowHTTP := fs.Bool("allow-http", cfg.RulesAllowHTTP, "permit a plain-http -url; https-to-http redirects stay refused (MAILSTRIX_RULES_ALLOW_HTTP)")
	timeout := fs.Duration("timeout", 60*time.Second, "overall HTTP timeout")
	allowDrop := fs.Bool("allow-count-drop", cfg.AllowRulesCountDrop, "install a bundle with zero rules or under half the current rule count (MAILSTRIX_RULES_ALLOW_COUNT_DROP)")
	verifyOnly := fs.Bool("verify-only", false, "verify into a fresh temporary cache and remove it; never touch the configured cache")
	expectedVersion := fs.Int("expected-version", 0, "with -verify-only, require this published version")
	requireMarker := fs.Bool("require-marker", false, "with -verify-only, fail unless the published marker tree verifies and loads against this binary")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *requireMarker && !*verifyOnly {
		fmt.Fprintln(os.Stderr, "require-marker requires verify-only")
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
	// object store, so a blanket reject would break the default URL). These
	// requests carry no auth/secret header, but the bundle and manifest are the
	// rules we load, so their transport matters: mailstrix.FetchRules requires an
	// https URL (http only with -allow-http), refuses any https-to-http redirect
	// even then, and caps the chain at 10 hops on its own copy of this client.
	// This local hop cap is kept and runs after those checks.
	hc := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	if *allowDrop {
		ctx = mailstrix.WithAllowRuleCountDrop(ctx)
	}
	// Additional operator trust anchors are resolved (and loudly logged) before
	// the fetch; a malformed key aborts instead of quietly narrowing trust to
	// the embedded keys. The published manifest must carry a valid ed25519
	// signature from one of these keys or the update is refused.
	if err := cfg.ValidateRulesSigningKeys(); err != nil {
		fmt.Fprintln(os.Stderr, "strixd fetch-rules:", err)
		return 2
	}
	extraKeys, err := cfg.ExtraRulesSigningKeys()
	if err != nil {
		fmt.Fprintln(os.Stderr, "strixd fetch-rules:", err)
		return 2
	}
	// MAILSTRIX_RULES_MARKERS=auto|off; an invalid value aborts before any request.
	if err := cfg.ValidateRulesMarkers(); err != nil {
		fmt.Fprintln(os.Stderr, "strixd fetch-rules:", err)
		return 2
	}
	res, err := mailstrix.FetchRulesWithOptions(ctx, *url, *cacheDir, libyaraVersion, hc, mailstrix.FetchRulesOptions{AllowHTTP: *allowHTTP, ExtraSigningKeys: extraKeys, Markers: cfg.RulesMarkers})
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
		fmt.Printf("verify-rules: marker=%s\n", res.Marker)
		if *requireMarker {
			if err := requireMarkerInstalled(res.Marker); err != nil {
				fmt.Fprintln(os.Stderr, "verify-rules:", err)
				return 2
			}
		}
		return 0
	}
	if res.Updated {
		fmt.Printf("fetch-rules: %s — restart or SIGHUP strixd to load the new bundle\n", res.Reason)
		fmt.Printf("fetch-rules: marker tree %s\n", res.Marker)
	} else {
		fmt.Printf("fetch-rules: %s\n", res.Reason)
	}
	return 0
}

// requireMarkerInstalled is the -require-marker gate: only a marker tree that
// was downloaded, hash-checked, extracted and loaded by this binary's loader
// counts. Every other outcome (no field, disabled, wrong toolchain, invalid
// field or tree) is a failure, so a publisher can refuse a candidate whose tree
// would silently fall back to the full ruleset on clients.
func requireMarkerInstalled(status string) error {
	if status != mailstrix.MarkerStatusInstalled {
		return fmt.Errorf("marker tree required but status is %q", status)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
