# Build input pins

Dockerfiles pin external images by multi-platform index digest. The selected
Debian bookworm-slim, Go 1.25.13-bookworm, distroless base-debian12:nonroot and
Dockerfile frontend indexes include both linux/amd64 and linux/arm64.
Tags remain readable version labels; the digest selects the actual content.
Update both together when changing Go versions.

The input sources checked on 2026-09-05 were:

- Debian and Go: the official `library/debian:bookworm-slim` and
  `library/golang:1.25.13-bookworm` manifests on Docker Hub.
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

`sh packaging/deb/workflow_pins_test.sh` checks recursive GitHub workflows and
composite actions, root Dockerfiles, and Dockerfiles below `docker/` and
`contrib/`. It decodes workflow YAML before inspecting every `uses:` and `run:`
value, so equivalent block, flow, quoted and multiline forms cannot bypass the
policy. Its download checks accept the reviewed fail-fast command sequence; they
do not attempt to interpret arbitrary shell programs. Write exact `go install`
versions directly at each install site; output or environment substitutions are
rejected. Run
`python3 -B packaging/deb/workflow_pins_controls_test.py` to exercise benign
fixtures for missing pins and checksums. Both commands run in CI.

The Postfix integration image may consume the local `strixd-test` image only
when the expected CI build produces it from this checkout. External bases
still require digests. Public YARA rule feeds retain their separate update
policy; these source/build-tool pins do not freeze those feeds or Debian apt
repositories.
