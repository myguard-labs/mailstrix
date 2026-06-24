package oleparse

const (
	// Limit the size of the document
	MAX_SECTORS = 1024 * 1024

	sectorShiftV3 = 0x9
	sectorShiftV4 = 0xC

	// MAX_DECOMPRESSED bounds DecompressStream output. MS-OVBA copy tokens can
	// expand a 4096-byte chunk window repeatedly; a crafted input (capped at
	// 64MiB upstream) could otherwise amplify to tens of GiB and OOM the
	// process. Legit VBA dir/source streams are well under this. Defense-in-
	// depth on top of the yarad-side amplifier bounds.
	MAX_DECOMPRESSED = 32 * 1024 * 1024 // 32 MiB

	// MAX_MODULES caps the VBA project module count. The uint16 field is already
	// dir_stream-bounded, but a generous explicit cap stops a degenerate
	// high-count header from driving a long parse loop. Mirrors the yarad-side
	// maxModules intent (kept generous; real projects are <<4096 modules).
	MAX_MODULES = 4096
)
