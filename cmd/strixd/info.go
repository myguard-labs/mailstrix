package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/eilandert/mailstrix/internal/extract"
	"github.com/eilandert/mailstrix/internal/mailstrix"
)

// cmdInfo prints yarad's build and rule-bundle provenance: the project repo +
// license, the binary version, the libyara it links, the extractor version, and
// — from the cache — which compiled rule bundle is loaded (its manifest version /
// generation date / source libyara). It is the at-a-glance "what exactly is
// running here" command, and the JSON form (-json) feeds tooling.
func cmdInfo(args []string) int {
	cfg := mailstrix.LoadConfig()

	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	cacheDir := fs.String("cache-dir", firstNonEmpty(cfg.CacheDir, "/var/cache/mailstrix"), "cache dir to read the loaded rules manifest from (MAILSTRIX_CACHE_DIR)")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	info := map[string]any{
		"version":           version,
		"libyara":           orUnknown(libyaraVersion),
		"extractor_version": extract.Version,
		"repo":              mailstrix.RepoURL,
		"home":              mailstrix.HomeURL,
		"license":           mailstrix.License,
	}
	if m, ok := mailstrix.LoadManifest(*cacheDir); ok {
		info["rules"] = map[string]any{
			"version":   m.Version,
			"generated": m.Generated,
			"libyara":   m.Libyara,
			"count":     m.Rules,
			"checksum":  m.Checksum,
		}
		srcs := m.Sources
		if len(srcs) == 0 {
			srcs = mailstrix.LoadSources("/usr/share/mailstrix")
		}
		if len(srcs) > 0 {
			info["sources"] = srcs
		}
	} else {
		info["rules"] = "no cached manifest (baked seed or uninitialised cache)"
		if srcs := mailstrix.LoadSources("/usr/share/mailstrix"); len(srcs) > 0 {
			info["sources"] = srcs
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			fmt.Fprintln(os.Stderr, "strixd info:", err)
			return 2
		}
		return 0
	}

	fmt.Printf("strixd %s\n", version)
	fmt.Printf("  libyara:    %s\n", orUnknown(libyaraVersion))
	fmt.Printf("  extractor:  %s\n", extract.Version)
	fmt.Printf("  repo:       %s\n", mailstrix.RepoURL)
	fmt.Printf("  home:       %s\n", mailstrix.HomeURL)
	fmt.Printf("  license:    %s\n", mailstrix.License)
	if m, ok := mailstrix.LoadManifest(*cacheDir); ok {
		fmt.Printf("  rules:      v%d, generated %s, libyara %s, %d rules\n",
			m.Version, m.Generated, m.Libyara, m.Rules)
		srcs := m.Sources
		if len(srcs) == 0 {
			srcs = mailstrix.LoadSources("/usr/share/mailstrix")
		}
		printSources(srcs)
	} else {
		fmt.Printf("  rules:      no cached manifest (baked seed or uninitialised cache at %s)\n", *cacheDir)
		printSources(mailstrix.LoadSources("/usr/share/mailstrix"))
	}
	return 0
}

func printSources(srcs []mailstrix.RuleSource) {
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
