package extract

import (
	"time"

	"www.velocidex.com/golang/oleparse"
)

const (
	maxOLEOrphans     = 8
	maxOLEOrphanBytes = 1 << 20
	noStream          = ^uint32(0)
)

func fromOLEOrphans(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || len(ole.Directory) == 0 || expired(deadline) {
		return
	}
	byID := make(map[uint32]*oleparse.Directory, len(ole.Directory))
	for _, d := range ole.Directory {
		if d != nil {
			byID[d.Index] = d
		}
	}
	root := byID[0]
	if root == nil || root.Header.Mse != 5 {
		return
	}
	used := map[uint32]bool{0: true}
	stack := []uint32{root.Header.SidChild}
	for len(stack) > 0 {
		if expired(deadline) {
			return
		}
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if id == noStream || used[id] {
			continue
		}
		d := byID[id]
		if d == nil {
			continue
		}
		used[id] = true
		stack = append(stack, d.Header.SidLeftSib, d.Header.SidRightSib)
		if d.Header.Mse == 1 || d.Header.Mse == 5 {
			stack = append(stack, d.Header.SidChild)
		}
	}
	carved := 0
	for _, d := range ole.Directory {
		if expired(deadline) || len(res.Streams) >= maxStreams || carved >= maxOLEOrphans {
			return
		}
		if d == nil || used[d.Index] || d.Header.Mse != 2 || d.Header.Size == 0 || d.Header.Size > maxOLEOrphanBytes {
			continue
		}
		var b []byte
		if d.Header.Size < ole.Header.MiniSectorCutoff {
			b = ole.ReadMiniChain(d.Header.SectStart)
		} else {
			b = ole.ReadChain(d.Header.SectStart)
		}
		// Clamp the chain to the declared size. Size is bounded to maxOLEOrphanBytes
		// by the filter above, so the int() conversion cannot overflow even on a
		// 32-bit host; the explicit cast keeps the slice index safe if that filter
		// is ever loosened.
		if size := int(d.Header.Size); size > 0 && len(b) > size {
			b = b[:size]
		}
		if len(b) > 0 {
			res.Streams = append(res.Streams, b)
			carved++
		}
	}
}
