package oleparse

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	OLE_DEBUG    *bool
	oleDebugOnce sync.Once
)

func DebugEnabled() bool {
	oleDebugOnce.Do(func() {
		if OLE_DEBUG != nil {
			return
		}

		value := false
		for _, x := range os.Environ() {
			if strings.HasPrefix(x, "OLE_DEBUG=1") {
				value = true
				break
			}
		}
		OLE_DEBUG = &value
	})
	return *OLE_DEBUG
}

func DebugPrintf(fmt_str string, args ...interface{}) {
	if DebugEnabled() {
		if !strings.HasSuffix(fmt_str, "\n") {
			fmt_str += "\n"
		}
		fmt.Printf(fmt_str, args...)
	}
}
