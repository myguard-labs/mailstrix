package mailstrix

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// procRSSBytes samples resident pages; 0 means unknown, preserving startup fallback.
func procRSSBytes() int64 { return procRSSBytesFrom("/proc/self/statm") }

func procRSSBytesFrom(path string) int64 {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed proc path in production; injectable for tests.
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	pageSize := int64(os.Getpagesize())
	if err != nil || pages <= 0 || pages > (1<<63-1)/pageSize {
		return 0
	}
	return pages * pageSize
}

// memoryStats contains the runtime-owned memory measurements, all in bytes.
type memoryStats struct{ HeapAlloc, HeapInuse, HeapReleased, Sys uint64 }

func goMemStats() memoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return memoryStats{HeapAlloc: m.HeapAlloc, HeapInuse: m.HeapInuse, HeapReleased: m.HeapReleased, Sys: m.Sys}
}
