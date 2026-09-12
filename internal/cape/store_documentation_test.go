package cape

import (
	"os"
	"strings"
	"testing"
)

func TestStoreExclusivityClaimsScopedToMountNamespace(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "store contract", path: "STORE.md"},
		{name: "operator guide", path: "../mailstrix/CAPE-OPERATIONS.md"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(strings.Fields(string(doc)), " ")
			for _, required := range []string{
				"current mount namespace",
				"cannot prove host-global exclusivity",
				"trusted host activation evidence",
			} {
				if !strings.Contains(text, required) {
					t.Errorf("storage assurance must state %q", required)
				}
			}
		})
	}
}
