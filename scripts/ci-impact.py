#!/usr/bin/env python3
"""Plan PR CI from changed paths, retaining full release/maintenance coverage.

Usage: ci-impact.py --base SHA --head SHA [--output FILE], or --full.
Inputs: Git diff (NUL-delimited; renames include both sides). Outputs: JSON and
optional GitHub job outputs. No builds, network or working-tree mutations.
Unmapped ordinary paths or unavailable diff data select full CI before outputs
are written. Unsafe paths and missing executable packaging contracts remain
errors. Extend RULES and GO_INPUTS when adding a new CI surface; test its
positive and unrelated cases in ci/.
"""

import argparse
import fnmatch
import json
import pathlib
import subprocess
import sys


class UnmappedPathError(ValueError):
    """A changed path has no registered CI consumer."""


# Every existing gate keeps its own scope, rather than a single scanners flag.
RULES = {
    "go": [],
    "native": [
        "docker/Dockerfile",
        "docker/compiler-input-capture.h",
        "docker/patch-compiler-input-capture.py",
        "docker/capture-compiler-inputs.py",
        "docker/export-compiler-inputs.py",
        "docker/build-marker-artifact.py",
        "docker/compile-rules.sh",
        "ci/compiler-input-check.sh",
        "ci/compiler_input_retention_test.py",
        "ci/compiler_input_export_test.py",
        "ci/marker_artifact_test.py",
        "ci/marker_runtime_fixture.py",
        "ci/prepare_marker_runtime.py",
        "ci/ci_marker_runtime_fixture_test.py",
        "ci/ci_marker_closure_test.py",
        "ci/compiler-input/io-faults.c",
        "ci/compiler-input/seek.c",
    ],
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
        "docker/capture-compiler-inputs.py",
        "docker/export-compiler-inputs.py",
        "docker/build-marker-artifact.py",
        "docker/compiler-input-capture.h",
        "docker/patch-compiler-input-capture.py",
        "docker/filter-rules.py",
        "scripts/smoke.sh",
        "ci/rules_polling_test.sh",
    ],
    "parity": [
        "docker/compiler-input-capture.h",
        "docker/patch-compiler-input-capture.py",
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
    "spamassassin": ["contrib/spamassassin/*", "ci/spamassassin_child_status.t"],
    "python": [
        "tools/parity/*.py",
        "tools/parity/comparator-pins.json",
        "docker/export-compiler-inputs.py",
        "docker/pack-marker-tree.py",
        "docker/build-marker-artifact.py",
        "ci/compiler_input_export_test.py",
        "ci/marker_artifact_test.py",
        "ci/marker_runtime_fixture.py",
        "ci/prepare_marker_runtime.py",
        "ci/ci_marker_runtime_fixture_test.py",
        "ci/ci_marker_closure_test.py",
    ],
    "prometheus": [
        "contrib/deploy/prometheus/*",
        "ci/mailstrix_memory_alerts_test.yml",
    ],
    "dependencies": ["go.mod", "go.sum", "osv-scanner.toml"],
    "workflows": [
        ".github/*.yml",
        ".github/*.yaml",
        "ci/ci_rules_signing_secret_test.py",
    ],
    "shell": ["*.sh", "contrib/sieve/strix-scan-wrapper"],
    "dockerfiles": [
        "*Dockerfile*",
        ".hadolint.yaml",
        "ci/ci_release_tag_test.py",
        "ci/ci_release_marker_toolchain_test.py",
        "ci/release_marker_image_test.sh",
        "ci/ci_release_local_artifacts_test.py",
        "docker/release-marker-toolchain.sh",
        "docker/release-local-artifacts.sh",
    ],
    "scope": [
        "tools/testscope/*",
        "ci/testscope_test.sh",
        "scripts/ci-*",
        "ci/ci_impact_test.py",
        "ci/generate_rules_cron_signer_test.sh",
        "ci/compiler-input-check.sh",
        "ci/compiler_input_retention_test.py",
        "ci/compiler_input_export_test.py",
        "ci/marker_artifact_test.py",
        "ci/marker_runtime_fixture.py",
        "ci/prepare_marker_runtime.py",
        "ci/ci_marker_runtime_fixture_test.py",
        "ci/ci_marker_closure_test.py",
        "ci/compiler-input/io-faults.c",
        "ci/compiler-input/seek.c",
        "ci/ci_go_checks_test.py",
        "ci/ci_batch_test.py",
        "ci/ci_lanes_test.py",
        "ci/ci_apt_install_test.py",
        "ci/ci_gh_install_test.py",
        "ci/ci_preflight_test.py",
        "ci/ci_profile_token_test.py",
        "ci/ci_xlm_rule_locator_test.py",
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
        "docker/export-compiler-inputs.py",
        "docker/pack-marker-tree.py",
        "docker/build-marker-artifact.py",
        "ci/generate_rules_count_test.sh",
        "ci/generate_rules_cron_signer_test.sh",
        "ci/ci_rules_signing_secret_test.py",
        "docker/generate-rules*",
        "cmd/strixd/*",
        # The publisher signs the manifest through cmd/rulessign, so a change
        # there changes what gets published; internal/rulespin holds the pinned
        # signing keys both the publisher and the client read.
        "cmd/rulessign/*",
        "internal/rulespin/*",
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
        "scripts/ci-test-batch.py",
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
    "filter": [
        "docker/filter-rules.py",
        "packaging/deb/filter_rules_test.sh",
        "ci/filter_rules_regex_test.py",
    ],
    "envkeys": [
        "ci/rules_polling_defaults_test.sh",
        "ci/dockerfile_rules_helpers_test.sh",
        "docker/Dockerfile",
        "docker/Dockerfile.release",
        "docker/docker-compose.yml",
        "docker/compile-rules.sh",
        "docker/fetch-rules.sh",
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
        "ci/ci_smoke_ownership_test.py",
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
        "ci/docker_context_selector_test.sh",
        "packaging/deb/dockerignore_test.sh",
        "packaging/deb/dockerignore_collision_test.sh",
    ],
}
# A PR must prove the release image whenever its binaries, marker toolchain,
# rules, or artifact-only CI route change. This is separate from the source
# image and generic Dockerfile lint selections.
RULES["release_image"] = [
    *(path for path in RULES["image"] if path != "docker/bake.ci.hcl"),
    "docker/Dockerfile.release",
    "NOTICE",
    "docker/release-marker-toolchain.sh",
    "docker/release-local-artifacts.sh",
    "ci/release_marker_image_test.sh",
    "ci/ci_release_tag_test.py",
    ".github/workflows/build-binaries.yml",
    ".github/workflows/nightly.yml",
    ".github/workflows/release.yml",
]
GO_INPUTS = [
    "ci/archive_decoder_incomplete_test.go",
    "ci/testdata/archive_decoder_incomplete_test.go",
    "ci/testdata/archive_decoder_http_test.go",
    "ci/icap_admission_ordering_test.go",
    "ci/testdata/icap_admission_ordering_test.go",
    "ci/icap_identity_test.go",
    "ci/testdata/icap_identity_test.go",
    "ci/clamd_admission_ordering_test.go",
    "ci/testdata/clamd_admission_ordering_test.go",
    "ci/cache_distribution/*.go",
    "ci/cache_byte_bound_test.go",
    "ci/local_scan_partial_test.go",
    "ci/feed_set_bytes_test.go",
    "ci/marker_runtime_fixture.py",
    "ci/prepare_marker_runtime.py",
    "ci/ci_marker_runtime_fixture_test.py",
    "ci/ci_marker_closure_test.py",
    "ci/marker_runtime_test.go",
    "ci/release_marker_loader_text_test.go",
    "docker/release-marker-toolchain.sh",
    "ci/testdata/marker-runtime.zip",
    "ci/extraction_memory_test.go",
    "ci/retained_limit_main_test.go",
    "ci/extraction-budget/*_test.go",
    "ci/rule_generations_test.go",
    "ci/p7_main_retirement_test.go",
    "ci/memory_metrics_test.go",
    "ci/startup_memory_test.go",
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
    "ci/status_log_test.go",
    "ci/verdict_envelope_test.go",
    "ci/reload_generation_test.go",
    "ci/marker_reload_test.go",
    "ci/rules_polling_config_test.go",
    "ci/rules_update_run_test.go",
    "ci/config_auto_derive_test.go",
    "ci/mime_attachment_hash_test.go",
    "ci/feed_lifecycle_helpers_test.go",
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
    "docker/compiler-input-capture.h",
    "docker/patch-compiler-input-capture.py",
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
    validated = []
    # Hard input/contract errors take precedence over ordinary unmapped paths,
    # independent of the order Git returns the changed files.
    for path in paths:
        if (
            not path
            or any(c.isspace() or ord(c) < 32 for c in path)
            or path.startswith("/")
            or ".." in path.split("/")
        ):
            raise ValueError(f"unsafe changed path: {path!r}")
        mapped = {key for key, patterns in RULES.items() if matches(path, patterns)}
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
        validated.append((path, mapped))
    for path, mapped in validated:
        selected.update(mapped)
        if not mapped and not matches(path, PASSIVE) and not matches(path, GO_INPUTS):
            raise UnmappedPathError(
                f"unmapped changed path: {path}; add its CI consumers"
            )
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
            if path in {
                "ci/testdata/marker-runtime.zip",
                "ci/marker_runtime_fixture.py",
                "ci/prepare_marker_runtime.py",
                "ci/ci_marker_runtime_fixture_test.py",
                "ci/ci_marker_closure_test.py",
            }:
                go_paths.add("internal/mailstrix/marker_artifact_test.go")
                go_paths.add("ci/marker_runtime_test.go")
                go_paths.add("internal/mailstrix/marker_closure_test.go")
            if path == "ci/testdata/rc4md5-biff.xls":
                go_paths.add("internal/extract/rc4md5_fixture_test.go")
            selected.add("go")
    if not full:
        for key in ("image", "release_image"):
            if not any(
                matches(p, RULES[key])
                and not p.endswith(("_test.go", ".md"))
                and "/testdata/" not in p
                for p in paths
            ):
                selected.discard(key)
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
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if not args.full and not args.base:
        parser.error("--base is required unless --full is used")
    if args.full:
        result = plan([], full=True)
    else:
        try:
            result = plan(changed_paths(args.base, args.head))
        except (
            OSError,
            subprocess.CalledProcessError,
            UnicodeError,
            UnmappedPathError,
        ) as error:
            if args.strict:
                raise
            print(f"ci-impact: {error}; selecting full CI", file=sys.stderr)
            result = plan([], full=True)
    if args.output:
        with args.output.open("a") as output:
            for key, value in result.items():
                output.write(
                    f"{key}={str(value).lower() if isinstance(value, bool) else value}\n"
                )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
