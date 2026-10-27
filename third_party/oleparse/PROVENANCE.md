# oleparse — local fork provenance

- Upstream: [Velocidex/go-oleparse](https://github.com/Velocidex/go-oleparse)
  (module path `www.velocidex.com/golang/oleparse`)
- Pinned version: v0.0.0-20251204214047-2e3e765e26a1
- Vendored upstream inputs: `oleparse.go`, `utils.go`, `limits.go`, `debug.go`
  and `LICENSE`. Upstream `cmd/`, tests and goldie/kingpin test dependencies are
  omitted. The other files in this directory are local module metadata,
  provenance and regression tests; keep them when refreshing the upstream
  inputs.

## Local changes

The fork is not a one-patch performance fork. Its current delta from the pinned
source includes:

- `_ReadChain` capacity pre-sizing, an indexed directory lookup and a bounded
  small-stream cache. Returned stream data is copied where caller mutation
  could otherwise poison cached data.
- Size- and prefix-bounded chain reads: `ReadChainSize`,
  `ReadMiniChainSize`, `ReadChainPrefix`, `ReadMiniChainPrefix`,
  `GetStreamPrefix` and the copy-returning `GetStreamView` API.
- Bounded VBA decompression and extraction: `DecompressStreamLimit`,
  `ExtractMacroBlobs`, `ExtractMacroBlobsLimited`, `ParseBufferBlobs` and
  `ParseBufferBlobsLimited`, plus per-module, cumulative-output and module-count
  limits. The legacy extraction entry points retain finite defaults.
- CFB structural validation for header sector shifts, FAT/DIF/MiniFAT counts
  and references, sparse directory SIDs, directory-name byte counts, v3/v4
  stream sizes, the fixed mini-stream cutoff and missing roots. Sector and
  parser offset arithmetic rejects sentinels, overflow, truncation and invalid
  ranges instead of wrapping or panicking.
- Bounded file/ZIP-member reads in `ParseFile`, including a finite member count
  and `.bin` filtering.
- UTF-16LE decoding for Unicode VBA metadata, independent of the ANSI code
  page.
- One-time, concurrency-safe debug configuration through `DebugEnabled`, while
  preserving the public `OLE_DEBUG` override.

## Re-vendor procedure

1. Obtain the exact pinned revision above and verify its revision before using
   it as the source. Do not infer compatibility from a newer upstream checkout.
2. Compare its four vendored `.go` inputs with this directory. Review every
   hunk against the complete local-change inventory above; the `_ReadChain`
   marker identifies only the original performance delta.
3. Replace only the five vendored upstream inputs. Keep `PROVENANCE.md`,
   `go.mod`, `go.sum` and every local `*_test.go` file, then reapply or port all
   local deltas before updating the pinned version in this document.
4. From the repository root, run the nested fork suite and the root consumers:

   ```sh
   (cd third_party/oleparse && go test -race -count=1 ./...)
   go test -race -count=1 ./internal/extract ./ci
   CHANGED_FILES='third_party/oleparse/oleparse.go' scripts/ci-go-checks.sh
   ```

These checks prove the local fork and its Mailstrix consumers at the selected
revision. They do not claim compatibility with unreviewed upstream revisions.
