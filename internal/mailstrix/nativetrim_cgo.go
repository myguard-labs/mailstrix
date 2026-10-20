//go:build cgo

package mailstrix

/*
#include <stdlib.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif

// strix_malloc_trim returns 1 when glibc trimmed, 0 on other libcs (musl has no
// malloc_trim and no per-thread arena retention to undo).
static int strix_malloc_trim(void) {
#ifdef __GLIBC__
	return malloc_trim(0);
#else
	return 0;
#endif
}
*/
import "C"

// nativeTrim hands freed libyara memory held in glibc malloc arenas back to the
// OS. A reload compiles/loads the new ruleset on whichever OS thread runs it, so
// glibc places those allocations in that thread's arena; freeing the old ruleset
// later leaves the pages resident (about +86 MiB RSS per reload, unbounded).
// malloc_trim(0) walks every arena and releases the free pages. It must run
// after the retired ruleset's finalizer has freed it; see armNativeTrim.
func nativeTrim() { C.strix_malloc_trim() }
