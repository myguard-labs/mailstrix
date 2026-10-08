#!/usr/bin/env python3
"""Plan PR CI from changed paths, retaining full release/maintenance coverage.

Usage: ci-impact.py --base SHA --head SHA [--output FILE], or --full.
Inputs: Git diff (NUL-delimited; renames include both sides). Outputs: JSON and
optional GitHub job outputs. No builds, network or working-tree mutations.
Unknown/unsafe paths fail before outputs are written. Extend RULES and GO_INPUTS
when adding a new CI surface; test its positive and unrelated cases in ci/.
"""

import argparse
import fnmatch
import json
import pathlib
import subprocess

# Every existing gate keeps its own scope, rather than a single scanners flag.
RULES = {
    "go": [],
    "image": [
        "cmd/*.go",
        "internal/*.go",
        "third_party/*",
        "go.mod",
        "go.sum",
        "docker/Dockerfile",
        "docker/bake.ci.hcl",
        ".dockerignore",
        "docker/local-rules/*",
        "docker/fetch-rules.sh",
        "docker/compile-rules.sh",
        "docker/filter-rules.py",
        "scripts/smoke.sh",
        "ci/rules_polling_test.sh",
    ],
    "parity": [
        "tools/parity/*",
        "internal/*",
        "third_party/*",
        "go.mod",
        "go.sum",
        "docker/Dockerfile",
        ".dockerignore",
        "docker/local-rules/*",
        "scripts/qualify-parity-isolation.sh",
    ],
    "postfix": [
        "contrib/postfix/*",
        "cmd/strix-milter/*.go",
        "cmd/strixd/*.go",
        "internal/*.go",
        "third_party/*",
        "go.mod",
        "go.sum",
        "docker/Dockerfile",
        ".dockerignore",
    ],
    "rspamd": ["contrib/rspamd/*", ".luacheckrc"],
    "spamassassin": ["contrib/spamassassin/*"],
    "python": ["tools/parity/*.py", "tools/parity/comparator-pins.json"],
    "prometheus": ["contrib/deploy/prometheus/*"],
    "dependencies": ["go.mod", "go.sum", "osv-scanner.toml"],
    "workflows": [".github/*.yml", ".github/*.yaml"],
    "shell": ["*.sh", "contrib/sieve/strix-scan-wrapper"],
    "dockerfiles": ["*Dockerfile*", ".hadolint.yaml", "ci/ci_release_tag_test.py"],
    "scope": [
        "tools/testscope/*",
        "ci/testscope_test.sh",
        "scripts/ci-*",
        "ci/ci_impact_test.py",
        "ci/ci_go_checks_test.py",
        "ci/vet_wiring_test.py",
        "ci/ci_integration_test.py",
        "ci/parity_cache_test.py",
        "ci/workflow_contract_test.py",
    ],
    "maintscript": [
        "packaging/deb/preremove.sh",
        "packaging/deb/postinstall.sh",
        "packaging/deb/postinstall-milter.sh",
        "packaging/deb/preremove-milter.sh",
        "packaging/deb/maintscript_test.sh",
    ],
    "generate": [
        "ci/generate_rules_count_test.sh",
        "docker/generate-rules*",
        "cmd/strixd/*",
        "internal/mailstrix/*",
        "docker/Dockerfile*",
        "docker/fetch-rules.sh",
        "docker/compile-rules.sh",
    ],
    "pins": [
        ".github/*",
        "packaging/deb/workflow_pins_test.sh",
        "packaging/deb/workflow_pins_controls_test.py",
        "packaging/deb/immutable_inputs_test.py",
    ],
    "qualification": [
        "scripts/qualify-parity-isolation.sh",
        "packaging/deb/parity_image_cleanup_test.py",
        "packaging/deb/parity_qualification_artifact_test.py",
        "ci/parity_cache_test.py",
        ".github/workflows/ci.yml",
    ],
    "runners": [".github/*", "packaging/deb/runner_isolation_test.sh"],
    "ruleargs": [
        "docker/Dockerfile",
        "docker/fetch-rules.sh",
        "docker/generate-rules.sh",
        "packaging/deb/rule_source_args_test.sh",
        "ci/fetch_rules_family_denylist_test.sh",
    ],
    "filter": ["docker/filter-rules.py", "packaging/deb/filter_rules_test.sh"],
    "envkeys": [
        "ci/rules_polling_defaults_test.sh",
        "docker/Dockerfile",
        "docker/Dockerfile.release",
        "docker/docker-compose.yml",
        "cmd/*",
        "internal/*",
        "packaging/deb/*.env",
        "packaging/deb/*.service",
        "packaging/deb/env_keys_test.sh",
        "packaging/deb/stop_timeout_test.sh",
    ],
    "readme": ["README.md", "packaging/deb/readme_install_test.sh"],
    "links": ["contrib/*", "README.md", "packaging/deb/contrib_links_test.sh"],
    "smoke": [
        "scripts/smoke.sh",
        "ci/rules_polling_test.sh",
        ".github/workflows/ci.yml",
        "packaging/deb/smoke_shared_test.sh",
    ],
    "benchmark": [
        ".github/workflows/maintenance.yml",
        ".github/workflows/ci.yml",
        "docker/Dockerfile",
        "packaging/deb/benchmark_command_test.sh",
    ],
    "dockerignore": [
        ".dockerignore",
        "*Dockerfile*",
        "packaging/deb/dockerignore_test.sh",
        "packaging/deb/dockerignore_collision_test.sh",
    ],
}
GO_INPUTS = [
    "ci/cape_response_test.go",
    "ci/cape_store_seam_test.go",
    "ci/decode_runs_test.go",
    "ci/decode_scalar_test.go",
    "ci/extract_cap_stops_test.go",
    "ci/extract_verify_first_member_test.go",
    "ci/extract_lzma_dict_cap_test.go",
    "ci/extract_lzma2_dict_cap_test.go",
    "ci/testdata/hdrenc-dir.7z",
    "ci/testdata/hdrenc-oversize.7z",
    "ci/testdata/hdrenc-small.7z",
    "ci/testdata/vfm-nonsolid.7z",
    "ci/testdata/vfm-solid.7z",
    "ci/testdata/vfm-onlybig.7z",
    "ci/testdata/lzmadict-enc-in.7z",
    "ci/testdata/lzmadict-enc-over.7z",
    "ci/testdata/lzmadict-hdrenc-over.7z",
    "ci/go_coverage.sh",
    "ci/go_coverage_test.py",
    "ci/clamd_cache_test.go",
    "ci/scanner_budget_test.go",
    "ci/streamdedupkey_test.go",
    "ci/reload_generation_test.go",
    "ci/marker_reload_test.go",
    "ci/rules_polling_config_test.go",
    "ci/config_auto_derive_test.go",
    "ci/mime_attachment_hash_test.go",
    "ci/mbazaar_lifecycle_test.go",
    "ci/threatfox_lifecycle_test.go",
    "ci/urlhaus_lifecycle_test.go",
    "ci/rar_password_extract_test.go",
    "ci/rc4md5_extract_test.go",
    "ci/testdata/rc4md5-biff.xls",
    "ci/urlhaus_shared_host_test.go",
    "cmd/*",
    "internal/*",
    "third_party/*",
    "tools/parity/*",
    "tools/testscope/*",
    "go.mod",
    "go.sum",
    "docker/Dockerfile",
    ".dockerignore",
    "docker/local-rules/*",
    "docker/fetch-rules.sh",
    "contrib/clamd/test_clients.py",
]
# Non-executable documentation/metadata plus surfaces with no gate in this CI.
PASSIVE = [
    "*.md",
    "LICENSE",
    "NOTICE",
    ".gitignore",
    ".github/*.webp",
    "contrib/sieve/*",
    "contrib/integrations/*",
    "contrib/clamd/*",
    "contrib/deploy/*",
    "docker/docker-compose.yml",
    "docker/pprof-capture.sh",
    "docker/profile/*",
    "docker/INPUTS.md",
    "docker/fetch-rules_test.sh",
    "packaging/deb/nfpm-strixd.yaml",
    "packaging/deb/nfpm-strix-scan.yaml",
    "packaging/deb/nfpm-strix-milter.yaml",
    "packaging/deb/strixd.sysusers",
    "packaging/deb/strix-milter.sysusers",
]


def matches(path, patterns):
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def plan(paths, full=False):
    paths = list(paths)
    selected = set(RULES) if full else set()
    go_paths = set()
    for path in paths:
        if (
            not path
            or any(c.isspace() or ord(c) < 32 for c in path)
            or path.startswith("/")
            or ".." in path.split("/")
        ):
            raise ValueError(f"unsafe changed path: {path!r}")
        mapped = {key for key, patterns in RULES.items() if matches(path, patterns)}
        selected.update(mapped)
        # Shell syntax is insufficient proof for new maintainer/helper behavior.
        # Require a named behavior contract before accepting executable packaging.
        if (
            path.startswith("packaging/deb/")
            and pathlib.PurePosixPath(path).suffix in {".sh", ".py"}
            and not (mapped - {"shell"})
        ):
            raise ValueError(
                f"unmapped executable packaging path: {path}; add its behavior contract"
            )
        if not mapped and not matches(path, PASSIVE) and not matches(path, GO_INPUTS):
            raise ValueError(f"unmapped changed path: {path}; add its CI consumers")
        if matches(path, GO_INPUTS) and (
            not path.endswith(".md")
            or path
            in {
                "internal/mailstrix/CAPE.md",
                "internal/cape/STORE.md",
                "internal/mailstrix/CAPE-OPERATIONS.md",
            }
        ):
            go_paths.add(path)
            # The binary fixture is read by both the public extraction tests
            # and the internal reference-producer consistency test.
            if path == "ci/testdata/rc4md5-biff.xls":
                go_paths.add("internal/extract/rc4md5_fixture_test.go")
            selected.add("go")
    if not full:
        if not any(
            matches(p, RULES["image"])
            and not p.endswith(("_test.go", ".md"))
            and "/testdata/" not in p
            for p in paths
        ):
            selected.discard("image")
        if not any(
            matches(p, RULES["parity"])
            and not p.endswith(".md")
            and (
                p.startswith("tools/parity/")
                or (not p.endswith("_test.go") and "/testdata/" not in p)
            )
            for p in paths
        ):
            selected.discard("parity")
        if not any(
            matches(p, RULES["postfix"])
            and not p.endswith(("_test.go", ".md"))
            and "/testdata/" not in p
            for p in paths
        ):
            selected.discard("postfix")
        for key in [
            "rspamd",
            "spamassassin",
            "python",
            "prometheus",
            "generate",
            "envkeys",
        ]:
            if not any(matches(p, RULES[key]) and not p.endswith(".md") for p in paths):
                selected.discard(key)
    # Changes to orchestration change every selection/check contract.
    if any(
        matches(
            p,
            [
                ".github/workflows/ci.yml",
                ".github/actions/*",
                "scripts/ci-*",
                "ci/ci_impact_test.py",
                "ci/ci_go_checks_test.py",
                "ci/ci_integration_test.py",
                "ci/workflow_contract_test.py",
            ],
        )
        for p in paths
    ):
        selected.update(RULES)
        # Exercise real Go tooling/test-stage wiring with the selector package,
        # whose behavior these orchestration edits control. Toolchain changes
        # have a broader, known impact on every package in the module graph.
        go_paths.add("tools/testscope/main.go")
        if any(p.startswith(".github/actions/go-setup/") for p in paths):
            go_paths.add("go.mod")
    result = {key: key in selected for key in RULES}
    result["changed_files"] = (
        "" if full else "--changed -- " + " ".join(sorted(go_paths))
    )
    result["docker"] = result["go"] or result["image"] or result["postfix"]
    return result


def changed_paths(base, head):
    # --no-renames reports a rename as deletion + addition, keeping both inputs.
    result = subprocess.run(
        ["git", "diff", "--no-renames", "--name-only", "-z", base, head, "--"],
        check=True,
        capture_output=True,
    )
    return result.stdout.decode().rstrip("\0").split("\0") if result.stdout else []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if not args.full and not args.base:
        parser.error("--base is required unless --full is used")
    result = plan([] if args.full else changed_paths(args.base, args.head), args.full)
    if args.output:
        with args.output.open("a") as output:
            for key, value in result.items():
                output.write(
                    f"{key}={str(value).lower() if isinstance(value, bool) else value}\n"
                )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
