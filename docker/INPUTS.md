# Build input pins

Dockerfiles pin external images by multi-platform index digest. The selected
Debian bookworm-slim, Go 1.26.8-bookworm, distroless base-debian12:nonroot and
Dockerfile frontend indexes include both linux/amd64 and linux/arm64.
Tags remain readable version labels; the digest selects the actual content.
Update both together when changing Go versions.

The input sources checked on 2026-09-05 were:

- Debian and Go: the official `library/debian:bookworm-slim` and
  `library/golang:1.26.8-bookworm` manifests on Docker Hub.
- Runtime: `gcr.io/distroless/base-debian12:nonroot` from the
  [distroless project](https://github.com/GoogleContainerTools/distroless).
- Build frontend: the official `docker/dockerfile:1` manifest on Docker Hub.
- Nested setup-go action: the upstream
  [v5 ref](https://github.com/actions/setup-go/tree/v5), resolved to the full
  commit recorded in `.github/actions/go-setup/action.yml`.
- YARA 4.5.2: SHA256 computed from the upstream
  [tag archive](https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.2.tar.gz).
  The recorded digest is a content pin, not an upstream signature assertion.
- nfpm 2.43.0: the amd64 Debian package digest from the upstream
  [checksums.txt](https://github.com/goreleaser/nfpm/releases/download/v2.43.0/checksums.txt).

Use `docker buildx imagetools inspect IMAGE:TAG` to resolve a replacement index
and check its platform list before updating a digest. Compare downloaded YARA
and nfpm bytes against their reviewed checksums before extraction or installation.
The three YARA build recipes must change together.
When changing an image digest or a YARA/nfpm version and checksum, update its
matching reviewed entry in `IMAGE_PINS`, `YARA_PINS`, or `NFPM_PINS` in
`packaging/deb/immutable_inputs_test.py` in the same commit.

`sh packaging/deb/workflow_pins_test.sh` checks recursive GitHub workflows,
composite actions, and Dockerfiles throughout the repository. It decodes
workflow YAML before inspecting `uses:` and `run:` values in executable schema
positions (`jobs.*`, `jobs.*.steps`, `runs.steps`, and isolated top-level test
steps), so equivalent block, flow, quoted and multiline forms cannot bypass the
policy. Dockerfile discovery excludes `.git`, `.venv`, `node_modules`, `target`,
`third_party`, and `vendor` dependency/build trees, and skips documentation
suffixes (`.json`, `.md`, `.rst`, `.txt`, `.yaml`, `.yml`). Both exclusions are
overridden when an executable workflow or reachable composite action selects the
file with `docker [buildx] build` (`-f PATH`, `-fPATH`, `--file PATH`, or
`--file=PATH`). Docker
continuations honor the declared `# escape=` parser directive, and reviewed
registry authorities are compared case-insensitively with default HTTPS ports
normalized. Its download checks accept the reviewed fail-fast command sequence;
they do not attempt to interpret arbitrary shell programs. Write exact
`go install` versions directly at each install site; dynamic command or
subcommand words and output or environment substitutions are rejected. Literal
commands passed to `sh -c`, `bash -c`, or `dash -c` are inspected recursively.
External image tokens must contain their literal digest, and repository-produced
image names must be literal too; an `ARG` default is not immutable because
`--build-arg` can replace it. Run
`python3 -B packaging/deb/workflow_pins_controls_test.py` to exercise benign
fixtures for missing pins and checksums. Both commands run in CI.

Any discovered Dockerfile that declares `ARG YARA_VERSION` or downloads from
`VirusTotal/yara` joins the YARA recipe set and must use the same reviewed
version and checksum as the three required recipes.

`.github/workflows/release.yml` must exist and contain exactly one
checksum-verified nfpm download/install recipe. Any nfpm recipe in another
`.github` YAML file must also be checksum-verified; the single-recipe
requirement applies only to `release.yml`.

The Postfix integration image may consume the local `strixd-test` image only
when the expected CI build produces it from this checkout. External bases
still require digests. Public YARA rule feeds retain their separate update
policy; these source/build-tool pins do not freeze those feeds or Debian apt
repositories.
