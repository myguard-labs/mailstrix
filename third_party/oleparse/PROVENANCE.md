# oleparse — local perf fork

- Upstream: https://github.com/Velocidex/go-oleparse
  (module path `www.velocidex.com/golang/oleparse`)
- Pinned version: v0.0.0-20251204214047-2e3e765e26a1
- Vendored: library `.go` files only (oleparse.go, utils.go, limits.go,
  debug.go) + LICENSE. `cmd/`, tests and goldie/kingpin test deps are omitted.

## Local change

`_ReadChain` (oleparse.go): pre-size the result buffer. The original appended
each sector into a zero-capacity slice, causing O(chain) reallocations and ~64%
of allocations on the extract path (per pprof). The fork adds a cheap first
pass that walks the FAT chain using ReadFat ONLY (same cycle detection, no
sector copy) to count sectors, then allocates the result slice once with
`make([]byte, 0, count*sectorSize)`. sectorSize is derived from the first
`ReadSector(start)` (full vs mini sectors differ), never hardcoded. Cycle and
invalid-sector early-return semantics are byte-for-byte identical to upstream.

To re-vendor: re-copy upstream library files and re-apply the `_ReadChain`
counting pass (see the `// local perf fork` markers).
