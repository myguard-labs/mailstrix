"""Exercise the real pin gate against harmless temporary repository fixtures."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import immutable_inputs_test as immutable_inputs

# Test names state their contract; method docstrings would only duplicate them.
# unittest owns TemporaryDirectory cleanup through enterContext.
# pylint: disable=missing-function-docstring,consider-using-with,too-many-public-methods


class TestWorkflowControls(unittest.TestCase):
    """Each fixture changes a single dependency class; nothing is downloaded."""

    def setUp(self) -> None:
        # enterContext owns cleanup for the full unittest case lifetime.
        temporary = self.enterContext(
            tempfile.TemporaryDirectory(prefix="mailstrix-pin-fixture-")
        )
        self.root = Path(temporary)
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: ./.github/actions/nested\n",
        )
        self.write(
            ".github/actions/nested/action.yml",
            "steps:\n  - uses: example/test@" + "a" * 40 + "\n",
        )
        self.write(
            "docker/Dockerfile",
            "FROM example.test/base:1@sha256:"
            + "1" * 64
            + "\n"
            + f"ARG YARA_VERSION={immutable_inputs.PinFixtures.yara_version}\n"
            + immutable_inputs.PinFixtures.yara
            + "\n",
        )
        for name in (
            "docker/Dockerfile.release",
            "docker/profile/Dockerfile.profile",
        ):
            self.write(
                name,
                f"ARG YARA_VERSION={immutable_inputs.PinFixtures.yara_version}\n"
                + immutable_inputs.PinFixtures.yara
                + "\n",
            )
        self.write(".github/workflows/release.yml", immutable_inputs.PinFixtures.nfpm)

    def write(self, name: str, content: str) -> None:
        """Create only static fixture text below the temporary root."""
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def gate(self) -> subprocess.CompletedProcess[str]:
        """Run the same shell entry point as CI with a fixture root."""
        return subprocess.run(
            [
                "sh",
                str(Path(__file__).with_name("workflow_pins_test.sh")),
                str(self.root),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    def reject(self, marker: str) -> None:
        """Require an observed failure from the expected policy arm."""
        result = self.gate()
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(marker, result.stdout)
        print(result.stdout.strip())

    def test_valid_fixture(self) -> None:
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("ALL OK", result.stdout)

    def test_nested_action_tag(self) -> None:
        self.write(
            ".github/actions/nested/action.yml", "steps:\n  - uses: example/test@v5\n"
        )
        self.reject("third-party action(s) not pinned")

    def test_flow_style_action_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "jobs:\n  test:\n    steps: [{ uses: example/test@v5 }]\n",
        )
        self.reject("third-party action(s) not pinned")

    def test_explicit_uses_key_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - ? uses\n    : example/test@v5\n",
        )
        self.reject("third-party action(s) not pinned")

    def test_tagged_uses_key_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - !!str uses: example/test@v5\n",
        )
        self.reject("third-party action(s) not pinned")

    def test_multiline_uses_value_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses:\n      example/test@v5\n",
        )
        self.reject("third-party action(s) not pinned")

    def test_escaped_uses_key_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            'steps:\n  - "\\u0075ses": example/test@v5\n',
        )
        self.reject("third-party action(s) not pinned")

    def test_escaped_flow_uses_key_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            'steps: [{ "\\u0075ses": example/test@v5 }]\n',
        )
        self.reject("third-party action(s) not pinned")

    def test_alias_mapping_key_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            'env:\n  KEY: &u "\\u0075ses"\nsteps:\n  - *u: example/test@v5\n',
        )
        self.reject("third-party action(s) not pinned")

    def test_quoted_uses_key_is_scanned(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            'steps:\n  - "uses": example/test@v5\n',
        )
        self.reject("third-party action(s) not pinned")

    def test_go_install_variable_version_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run: go install example.test/tool@${TOOL_VERSION}\n",
        )
        self.reject("go install without an exact pinned version")

    def test_go_install_output_version_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n"
            "  - id: pins\n"
            "    run: |\n"
            '      echo "tool=v1.2.3" >> "$GITHUB_OUTPUT"\n'
            "  - env:\n"
            "      TOOL_VERSION: ${{ steps.pins.outputs.tool }}\n"
            '    run: go install "example.test/tool@${TOOL_VERSION}"\n',
        )
        self.reject("go install without an exact pinned version")

    def test_folded_go_install_is_rejected(self) -> None:
        for header in (">", ">-", ">+", ">2", ">2-", ">-2"):
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: {header}\n      go install\n      example.test/tool@latest\n",
            )
            self.reject("go install without an exact pinned version")

    def test_plain_multiline_go_install_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run: go install\n      example.test/tool@latest\n",
        )
        self.reject("go install without an exact pinned version")

    def test_go_install_whitespace_variants_are_rejected(self) -> None:
        for separator in ("  ", "\t"):
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: |\n      go{separator}install example.test/tool@latest\n",
            )
            self.reject("go install without an exact pinned version")

    def test_go_install_shell_continuation_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run: |\n      go \\\n        install example.test/tool@latest\n",
        )
        self.reject("go install without an exact pinned version")

    def test_go_install_shell_quoting_is_rejected(self) -> None:
        cases = (
            ('"go" "install" example.test/tool@latest', "exact pinned version"),
            ("'go' install example.test/tool@latest", "exact pinned version"),
            ("go 'install' example.test/tool@latest", "exact pinned version"),
            (r"g\o in\stall example.test/tool@latest", "exact pinned version"),
            ('g""o in""stall example.test/tool@latest', "exact pinned version"),
            ("g$'o' in$'stall' example.test/tool@latest", "unsupported command syntax"),
            (
                r"g$'\x6f' install example.test/tool@latest",
                "unsupported command syntax",
            ),
            (
                r"g$'\157' install example.test/tool@latest",
                "unsupported command syntax",
            ),
            (
                "g${EMPTY}o in${EMPTY}stall example.test/tool@latest",
                "unsupported command syntax",
            ),
            (
                "g${EMPTY:-}o in${EMPTY:-}stall example.test/tool@latest",
                "unsupported command syntax",
            ),
            (
                "g$(echo o) install example.test/tool@latest",
                "unsupported command syntax",
            ),
            (
                "g`echo o` install example.test/tool@latest",
                "unsupported command syntax",
            ),
            ("$GO install example.test/tool@latest", "unsupported command syntax"),
        )
        for command, marker in cases:
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: |\n      {command}\n",
            )
            self.reject(marker)

    def test_dynamic_go_subcommands_are_rejected(self) -> None:
        commands = (
            "go ${CMD:-install} example.test/tool@latest",
            "go inst${X:-all} example.test/tool@latest",
            "go ins$(printf tall) example.test/tool@latest",
            "go ins`printf tall` example.test/tool@latest",
            "$GO $INSTALL example.test/tool@latest",
            "${GO} ${INSTALL} example.test/tool@latest",
            "$(printf go) $(printf install) example.test/tool@latest",
        )
        for command in commands:
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: |\n      {command}\n",
            )
            self.reject("unsupported command syntax")

    def test_nested_shell_go_install_is_rejected(self) -> None:
        for shell in ("sh", "bash", "dash"):
            self.write(
                ".github/workflows/ci.yml",
                "steps:\n"
                f"  - run: {shell} -c 'go install example.test/tool@latest'\n",
            )
            self.reject("go install without an exact pinned version")

    def test_nested_shell_flag_clusters_are_rejected(self) -> None:
        for flags in ("-cx", "-ec", "-cex"):
            self.write(
                ".github/workflows/ci.yml",
                "steps:\n"
                f"  - run: sh {flags} 'go install example.test/tool@latest'\n",
            )
            self.reject("go install without an exact pinned version")

    def test_nested_shell_options_after_c_are_rejected(self) -> None:
        for shell in ("sh", "bash", "dash"):
            self.write(
                ".github/workflows/ci.yml",
                "steps:\n"
                f"  - run: {shell} -c -x "
                "'go install example.test/tool@latest'\n",
            )
            self.reject("go install without an exact pinned version")

    def test_go_install_through_wrappers_is_rejected(self) -> None:
        commands = (
            "sudo go install example.test/tool@latest",
            "sudo -u root go install example.test/tool@latest",
            "timeout 60 go install example.test/tool@latest",
            "time go install example.test/tool@latest",
            "stdbuf -oL go install example.test/tool@latest",
            "xargs go install example.test/tool@latest",
        )
        for command in commands:
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: {command}\n",
            )
            self.reject("go install without an exact pinned version")

    def test_go_install_argument_text_is_accepted(self) -> None:
        for command in (
            "echo go install example.test/tool@latest",
            "printf '%s\\n' go install example.test/tool@latest",
            "set -- go install example.test/tool@latest",
        ):
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: {command}\n",
            )
            result = self.gate()
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_go_install_global_directory_flag_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run: go -C . install example.test/tool@latest\n",
        )
        self.reject("go install without an exact pinned version")

    def test_go_install_unbalanced_quote_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run: |\n      go install 'example.test/tool@latest\n",
        )
        self.reject("invalid shell quoting")

    def test_non_scalar_run_value_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run:\n      - go install example.test/tool@latest\n",
        )
        self.reject("run value must be a scalar")

    def test_exact_go_versions_with_redirections_are_accepted(self) -> None:
        for command in (
            "go install example.test/tool@v1.2.3 2>/dev/null",
            "go install example.test/tool@v1.2.3 2>>/dev/null",
            "go install example.test/tool@v2.0.0+incompatible 2>&1",
        ):
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: |\n      {command}\n",
            )
            result = self.gate()
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_comments_cannot_hide_go_install(self) -> None:
        for content in (
            "steps:\n  # comment \\\n  - run: go install example.test/tool@latest\n",
            "steps:\n  - run: |\n      # comment \\\n      go install example.test/tool@latest\n",
        ):
            self.write(".github/workflows/ci.yml", content)
            self.reject("go install without an exact pinned version")

    def test_quoted_multiline_go_install_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            'steps:\n  - run: "go install\n      example.test/tool@latest"\n',
        )
        self.reject("go install without an exact pinned version")

    def test_nonexecution_run_and_uses_keys_are_accepted(self) -> None:
        for content in (
            "defaults: { run: { shell: bash } }\n",
            "env: { uses: harmless }\n",
            "steps:\n  - run: cargo install cargo-edit --version 0.13.0\n",
            'steps:\n  - run: echo "go install example.test/tool@latest"\n',
            "x: &x\n  self: *x\n",
        ):
            self.write(".github/workflows/ci.yml", content)
            result = self.gate()
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_local_action_outside_dot_github_is_scanned(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: ./ci/actions/nested\n",
        )
        self.write(
            "ci/actions/nested/action.yml",
            "runs:\n  steps:\n    - uses: example/test@v5\n",
        )
        self.reject("third-party action(s) not pinned")

    def test_local_action_path_with_spaces_is_scanned(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: ./ci/actions/space dir\n",
        )
        self.write(
            "ci/actions/space dir/action.yml",
            "runs:\n  steps:\n    - uses: example/test@v5\n",
        )
        self.reject("third-party action(s) not pinned")

    def test_missing_dot_github_actions_is_valid(self) -> None:
        shutil.rmtree(self.root / ".github/actions")
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: example/test@" + "a" * 40 + "\n",
        )
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_nested_action_inconsistent_sha(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: example/test@" + "b" * 40 + "\n",
        )
        self.reject("inconsistent pinned action SHAs")

    def test_action_identity_case_is_consistent(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: Example/Test@" + "b" * 40 + "\n",
        )
        self.reject("inconsistent pinned action SHAs")

    def test_action_repository_subpaths_share_pin(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: Example/Test/Action@"
            + "a" * 40
            + "\n  - uses: example/test/action@"
            + "b" * 40
            + "\n",
        )
        self.reject("inconsistent pinned action SHAs")

    def test_tool_cache_key_tracks_workflow_and_go_setup(self) -> None:
        for cache_path in (
            "~/go/bin",
            "~/go/bin/",
            "~/go/bin/*",
            "~/go/bin/**",
            "~/go/bin/**/*",
            "~/go/bin/*/",
            "~/go/bin/**/bin",
            "$HOME/go/bin",
            "${HOME}/go/bin",
            "${{ env.HOME }}/go/bin",
            "${{env.HOME}}/go/bin",
            "${{  env.home  }}/go/bin",
            "~/go",
            "~/go/**",
            "~/go//bin",
            "/home/runner/go/bin",
            "/root/go/bin",
            "$GOPATH/bin",
            "${GOPATH}/bin",
            "${{ env.GOPATH }}/bin",
            "$GOPATH",
            "${GOPATH}",
            "${{ env.GOPATH }}",
            "${{env.GOPATH}}/bin",
            "${{  env.gopath  }}/bin",
            "~/go/./bin",
            "~/go/x/../bin",
            "/home/runner/go/./bin",
        ):
            self.write(
                ".github/workflows/ci.yml",
                "steps:\n"
                "  - uses: actions/cache@" + "a" * 40 + "\n"
                "    with:\n"
                f"      path: {cache_path}\n"
                "      key: gotools-static\n",
            )
            self.reject("cache key does not hash workflow and Go setup inputs")

    def test_gotools_cache_id_cannot_hide_its_path(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n"
            "  - id: gotools\n"
            "    uses: actions/cache@" + "a" * 40 + "\n"
            "    with:\n"
            "      path: ${{ env.CUSTOM_TOOLS }}\n"
            "      key: gotools-static\n",
        )
        self.reject("cache key does not hash workflow and Go setup inputs")

    def test_unrelated_cache_path_is_ignored(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n"
            "  - uses: actions/cache@" + "a" * 40 + "\n"
            "    with:\n"
            "      path: ~/go/pkg/mod\n"
            "      key: gomod-static\n",
        )
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_tool_cache_subactions_require_bound_keys(self) -> None:
        for action in ("restore", "save"):
            self.write(
                ".github/workflows/ci.yml",
                "steps:\n"
                f"  - uses: actions/cache/{action}@" + "a" * 40 + "\n"
                "    with:\n"
                "      path: ~/go/bin\n"
                "      key: gotools-static\n",
            )
            self.reject("cache key does not hash workflow and Go setup inputs")

    def test_tool_cache_key_with_required_hash_is_accepted(self) -> None:
        expression = (
            "${{ hashFiles('.github/workflows/ci.yml', "
            "'.github/actions/go-setup/action.yml') }}"
        )
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n"
            "  - uses: actions/cache@" + "a" * 40 + "\n"
            "    with:\n"
            "      path: ~/go/bin\n"
            f'      key: "gotools-{expression}"\n',
        )
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_tool_cache_expression_in_unrelated_step_is_rejected(self) -> None:
        expected = (
            "hashFiles('.github/workflows/ci.yml', "
            "'.github/actions/go-setup/action.yml')"
        )
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n"
            f'  - run: echo "{expected}"\n'
            "  - uses: actions/cache@" + "a" * 40 + "\n"
            "    with:\n"
            "      path: ~/go/bin\n"
            "      key: gotools-static\n",
        )
        self.reject("cache key does not hash workflow and Go setup inputs")

    def test_tool_cache_key_expression_decoys_are_rejected(self) -> None:
        expression = (
            "hashFiles('.github/workflows/ci.yml', "
            "'.github/actions/go-setup/action.yml')"
        )
        for key in (expression, "${{ '" + expression + "' }}"):
            self.write(
                ".github/workflows/ci.yml",
                "steps:\n"
                "  - uses: actions/cache@" + "a" * 40 + "\n"
                "    with:\n"
                "      path: ~/go/bin\n"
                f'      key: "{key}"\n',
            )
            self.reject("cache key does not hash workflow and Go setup inputs")

    def test_nested_docker_base_tag(self) -> None:
        self.write("docker/nested/Dockerfile.test", "FROM example.test/base:1\n")
        self.reject("Docker external base must have a sha256 digest")

    def test_build_arg_cannot_override_external_base(self) -> None:
        self.write(
            "docker/nested/Dockerfile.test",
            "ARG BASE=example.test/base:1@sha256:" + "1" * 64 + "\n"
            "FROM ${BASE}\n",
        )
        self.reject("use a literal token")

    def test_dockerfile_outside_known_directories(self) -> None:
        for name in (
            "Dockerfile",
            "build.Dockerfile",
            "service.dockerfile",
            "Containerfile",
        ):
            self.write(f"packaging/tools/{name}", "FROM example.test/base:1\n")
            self.reject("Docker external base must have a sha256 digest")
            (self.root / "packaging/tools" / name).unlink()

    def test_dependency_tree_dockerfiles_are_excluded(self) -> None:
        self.write("vendor/example/Dockerfile", "FROM example.test/base:1\n")
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_non_utf8_dockerfile_fails_as_policy_not_traceback(self) -> None:
        path = self.root / "packaging/tools/Dockerfile.binary"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"FROM example.test/base:1\n# \xff\n")
        result = self.gate()
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Docker external base must have a sha256 digest", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_dockerfile_documentation_is_ignored(self) -> None:
        self.write("packaging/tools/Dockerfile.md", "FROM example.test/base:1\n")
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_explicit_workflow_dockerfile_is_always_scanned(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run: docker build -f packaging/tools/Dockerfile.yml .\n",
        )
        self.write(
            "packaging/tools/Dockerfile.yml", "FROM example.test/base:latest\n"
        )
        self.reject("Docker external base must have a sha256 digest")

    def test_explicit_dockerfile_overrides_tree_exclusions(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run: docker buildx build "
            "--file=vendor/example/build.yml .\n",
        )
        self.write("vendor/example/build.yml", "FROM example.test/base:latest\n")
        self.reject("Docker external base must have a sha256 digest")

    def test_wrapped_docker_build_file_is_scanned(self) -> None:
        self.write("vendor/example/build.yml", "FROM example.test/base:latest\n")
        for command in (
            "sudo docker build -f vendor/example/build.yml .",
            "timeout 600 docker buildx build --file=vendor/example/build.yml .",
        ):
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: {command}\n",
            )
            self.reject("Docker external base must have a sha256 digest")

    def test_docker_global_options_do_not_hide_build_file(self) -> None:
        self.write("vendor/example/build.yml", "FROM example.test/base:latest\n")
        for command in (
            "docker --context ci build -f vendor/example/build.yml .",
            (
                "docker --log-level debug buildx build "
                "--file=vendor/example/build.yml ."
            ),
            (
                "docker -H unix:///run/docker.sock build "
                "-fvendor/example/build.yml ."
            ),
        ):
            self.write(
                ".github/workflows/ci.yml",
                f"steps:\n  - run: {command}\n",
            )
            self.reject("Docker external base must have a sha256 digest")

    def test_reachable_external_composite_dockerfile_is_scanned(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: ./ci/actions/build\n",
        )
        self.write(
            "ci/actions/build/action.yml",
            "runs:\n"
            "  using: composite\n"
            "  steps:\n"
            "    - shell: sh\n"
            "      run: docker build -f vendor/example/build.yml .\n",
        )
        self.write("vendor/example/build.yml", "FROM example.test/base:latest\n")
        self.reject("Docker external base must have a sha256 digest")

    def test_backtick_escape_cannot_hide_external_mount_source(self) -> None:
        for instruction in (
            "RUN --mount=type=bind,`\n    from=alpine:3.20,target=/src true",
            "COPY --from=`\n    alpine:3.20 /src /dest",
        ):
            self.write(
                "packaging/tools/Dockerfile.escape",
                "# escape=`\nFROM scratch\n" + instruction + "\n",
            )
            self.reject("Docker external base must have a sha256 digest")

    def test_docker_comments_never_continue(self) -> None:
        for directive, escape in (("", "\\"), ("# escape=`\n", "`")):
            self.write(
                "packaging/tools/Dockerfile.comment",
                directive
                + "FROM scratch\n"
                + f"# harmless note {escape}\n"
                + "FROM example.test/base:latest\n",
            )
            self.reject("Docker external base must have a sha256 digest")

    def test_comments_inside_docker_continuations_are_skipped(self) -> None:
        for directive, escape in (("", "\\"), ("# escape=`\n", "`")):
            self.write(
                "packaging/tools/Dockerfile.comment",
                directive
                + "FROM scratch\n"
                + f"RUN --mount=type=bind,{escape}\n"
                + "    # harmless note\n"
                + "    from=alpine:3.20,target=/src true\n",
            )
            self.reject("Docker external base must have a sha256 digest")

    def test_reviewed_gcr_image_aliases_remain_bound(self) -> None:
        digest = immutable_inputs.IMAGE_PINS[
            "gcr.io/distroless/base-debian12:nonroot"
        ]
        for host in ("GCR.IO", "gcr.io:443", "gcr.io:0443", "gcr.io."):
            self.write(
                "packaging/tools/Dockerfile.gcr",
                f"FROM {host}/distroless/base-debian12:nonroot@sha256:"
                + "2" * 64
                + "\n",
            )
            self.reject("label/digest pair does not match the reviewed pin")
            self.write(
                "packaging/tools/Dockerfile.gcr",
                f"FROM {host}/distroless/base-debian12:nonroot@sha256:{digest}\n",
            )
            result = self.gate()
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_contrib_docker_base_tag(self) -> None:
        self.write(
            "contrib/postfix/Dockerfile.integration", "FROM example.test/base:1\n"
        )
        self.reject("Docker external base must have a sha256 digest")

    def test_local_integration_image(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "      run: |\n"
            "        docker buildx build --target test -f docker/Dockerfile "
            "-t strixd-test --load .\n",
        )
        self.write(
            "contrib/postfix/Dockerfile.integration",
            "FROM strixd-test AS binaries\n",
        )
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_build_arg_cannot_override_local_integration_image(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "      run: |\n"
            "        docker buildx build --target test -f docker/Dockerfile "
            "-t strixd-test --load .\n",
        )
        self.write(
            "contrib/postfix/Dockerfile.integration",
            "ARG BUILD_IMAGE=strixd-test\nFROM ${BUILD_IMAGE} AS binaries\n",
        )
        self.reject("use a literal token")

    def test_local_image_requires_ci_producer(self) -> None:
        self.write(
            "contrib/postfix/Dockerfile.integration",
            "ARG BUILD_IMAGE=strixd-test\nFROM ${BUILD_IMAGE} AS binaries\n",
        )
        self.reject("Docker external base must have a sha256 digest")

    def test_missing_ci_workflow_fails_without_traceback(self) -> None:
        (self.root / ".github/workflows/ci.yml").unlink()
        self.write(
            "contrib/postfix/Dockerfile.integration",
            "ARG BUILD_IMAGE=strixd-test\nFROM ${BUILD_IMAGE} AS binaries\n",
        )
        self.reject("Docker external base must have a sha256 digest")

    def test_yara_without_checksum(self) -> None:
        path = self.root / "docker/Dockerfile"
        self.write(
            "docker/Dockerfile",
            path.read_text(encoding="utf-8").replace("sha256sum -c -", "true"),
        )
        self.reject("YARA download must verify")

    def test_required_yara_recipe_cannot_disappear(self) -> None:
        self.write(
            "docker/Dockerfile.release",
            "FROM example.test/base:1@sha256:" + "1" * 64 + "\n",
        )
        self.reject("unreadable YARA build pin")

    def test_yara_recipes_must_change_together(self) -> None:
        path = self.root / "docker/profile/Dockerfile.profile"
        self.write(
            "docker/profile/Dockerfile.profile",
            path.read_text(encoding="utf-8").replace(
                immutable_inputs.PinFixtures.yara_digest, "2" * 64
            ),
        )
        self.reject("YARA build recipes must use the same version and checksum")

    def test_added_yara_recipe_uses_reviewed_pin(self) -> None:
        self.write(
            "contrib/new/Dockerfile",
            f"ARG YARA_VERSION={immutable_inputs.PinFixtures.yara_version}\n"
            + immutable_inputs.PinFixtures.yara.replace(
                immutable_inputs.PinFixtures.yara_digest, "2" * 64
            )
            + "\n",
        )
        self.reject("YARA build recipes must use the same version and checksum")

    def test_comment_only_yara_reference_is_accepted(self) -> None:
        self.write(
            "contrib/new/Dockerfile",
            "FROM example.test/base:1@sha256:"
            + "1" * 64
            + "\n# Documentation: github.com/VirusTotal/yara/releases\n",
        )
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_consistent_unreviewed_yara_pin_is_rejected(self) -> None:
        for name in immutable_inputs.YARA_RECIPE_PATHS:
            path = self.root / name
            self.write(
                name,
                path.read_text(encoding="utf-8").replace(
                    immutable_inputs.PinFixtures.yara_digest, "2" * 64
                ),
            )
        self.reject("YARA version/checksum pair does not match the reviewed pin")

    def test_nfpm_version_checksum_pair_is_reviewed(self) -> None:
        self.write(
            ".github/workflows/release.yml",
            immutable_inputs.PinFixtures.nfpm.replace(
                immutable_inputs.PinFixtures.nfpm_version, "9.99.99"
            ),
        )
        self.reject("nfpm version/checksum pair does not match the reviewed pin")

    def test_nfpm_without_checksum(self) -> None:
        self.write(
            ".github/workflows/release.yml",
            immutable_inputs.PinFixtures.nfpm.replace("sha256sum -c -", "true"),
        )
        self.reject("nfpm download must verify")

    def test_required_nfpm_recipe_cannot_disappear(self) -> None:
        self.write(".github/workflows/release.yml", "name: release\n")
        self.reject("nfpm download must verify")

    def test_deleted_release_workflow_is_rejected(self) -> None:
        (self.root / ".github/workflows/release.yml").unlink()
        self.reject("missing required nfpm release workflow")

    def test_nfpm_alternate_host_and_install_spelling_are_rejected(self) -> None:
        self.write(
            ".github/workflows/release.yml",
            immutable_inputs.PinFixtures.nfpm.replace("github.com", "github.com:443"),
        )
        self.reject("nfpm download must verify")
        self.write(
            ".github/workflows/release.yml",
            immutable_inputs.PinFixtures.nfpm.replace("dpkg -i", "dpkg --install"),
        )
        self.reject("nfpm download must verify")

    def test_comment_beside_nfpm_recipe_is_accepted(self) -> None:
        content = immutable_inputs.PinFixtures.nfpm.replace(
            "      set -euo pipefail\n",
            "      # github.com/goreleaser/nfpm/ release recipe\n"
            "      set -euo pipefail\n",
        )
        self.write(".github/workflows/release.yml", content)
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_nfpm_yaml_block_scalar_variants_are_accepted(self) -> None:
        # The fixture body uses the two-space indentation selected by |2.
        for header in ("|-", "|+", "|2"):
            content = immutable_inputs.PinFixtures.nfpm.replace(
                "run: |", f"run: {header}"
            )
            self.write(".github/workflows/release.yml", content)
            result = self.gate()
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_non_utf8_github_yaml_does_not_traceback(self) -> None:
        path = self.root / ".github/workflows/extra.yml"
        path.write_bytes(b"name: extra # \xff\n")
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
