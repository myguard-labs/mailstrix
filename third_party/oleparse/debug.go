package oleparse

import (
	"fmt"
	"os"
	"strings"
)

var (
	OLE_DEBUG *bool
)

func DebugEnabled() bool {
	if OLE_DEBUG == nil {
		value := false
		OLE_DEBUG = &value

		for _, x := range os.Environ() {
			if strings.HasPrefix(x, "OLE_DEBUG=1") {
				value = true
				break
			}
		}

	}
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
