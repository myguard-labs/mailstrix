package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/eilandert/rspamd-yarad/internal/extract"
	"github.com/eilandert/rspamd-yarad/internal/yarad"
)

// cmdInfo prints yarad's build and rule-bundle provenance: the project repo +
// license, the binary version, the libyara it links, the extractor version, and
// — from the cache — which compiled rule bundle is loaded (its manifest version /
// generation date / source libyara). It is the at-a-glance "what exactly is
// running here" command, and the JSON form (-json) feeds tooling.
func cmdInfo(args []string) int {
	cfg := yarad.LoadConfig()

	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	cacheDir := fs.String("cache-dir", firstNonEmpty(cfg.CacheDir, "/var/cache/yarad"), "cache dir to read the loaded rules manifest from (YARAD_CACHE_DIR)")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	info := map[string]any{
		"version":           version,
		"libyara":           orUnknown(libyaraVersion),
		"extractor_version": extract.Version,
		"repo":              yarad.RepoURL,
		"license":           yarad.License,
	}
	if m, ok := yarad.LoadManifest(*cacheDir); ok {
		info["rules"] = map[string]any{
			"version":   m.Version,
			"generated": m.Generated,
			"libyara":   m.Libyara,
			"count":     m.Rules,
			"checksum":  m.Checksum,
		}
		srcs := m.Sources
		if len(srcs) == 0 {
			srcs = yarad.LoadSources("/usr/share/yarad")
		}
		if len(srcs) > 0 {
			info["sources"] = srcs
		}
	} else {
		info["rules"] = "no cached manifest (baked seed or uninitialised cache)"
		if srcs := yarad.LoadSources("/usr/share/yarad"); len(srcs) > 0 {
			info["sources"] = srcs
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			fmt.Fprintln(os.Stderr, "yarad info:", err)
			return 2
		}
		return 0
	}

	fmt.Printf("yarad %s\n", version)
	fmt.Printf("  libyara:    %s\n", orUnknown(libyaraVersion))
	fmt.Printf("  extractor:  %s\n", extract.Version)
	fmt.Printf("  repo:       %s\n", yarad.RepoURL)
	fmt.Printf("  license:    %s\n", yarad.License)
	if m, ok := yarad.LoadManifest(*cacheDir); ok {
		fmt.Printf("  rules:      v%d, generated %s, libyara %s, %d rules\n",
			m.Version, m.Generated, m.Libyara, m.Rules)
		srcs := m.Sources
		if len(srcs) == 0 {
			srcs = yarad.LoadSources("/usr/share/yarad")
		}
		printSources(srcs)
	} else {
		fmt.Printf("  rules:      no cached manifest (baked seed or uninitialised cache at %s)\n", *cacheDir)
		printSources(yarad.LoadSources("/usr/share/yarad"))
	}
	return 0
}

func printSources(srcs []yarad.RuleSource) {
	if len(srcs) == 0 {
		return
	}
	fmt.Printf("  sources:\n")
	for _, s := range srcs {
		set := ""
		if s.Set != "" {
			set = s.Set + "@"
		}
		fmt.Printf("    %-18s %s (%s, %s%s)\n", s.Name, s.Repo, s.License, set, s.Ref)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown (dev build)"
	}
	return s
}
