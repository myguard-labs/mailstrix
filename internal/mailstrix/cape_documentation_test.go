package mailstrix

import (
	"os"
	"strings"
	"testing"
)

// Parse the actual published example without resolving references, opening the
// store or starting the runtime. This catches schema drift in copyable docs.
func TestCAPEDocumentedConfiguration(t *testing.T) {
	doc, err := os.ReadFile("CAPE.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := strings.Split(string(doc), "```json\n")
	if len(blocks) != 2 {
		t.Fatal("expected exactly one documented JSON configuration")
	}
	raw, _, found := strings.Cut(blocks[1], "\n```")
	if !found {
		t.Fatal("documented configuration has no closing fence")
	}
	if _, err := parseCAPEDaemonConfig([]byte(raw)); err != nil {
		t.Fatalf("documented configuration rejected: %v", err)
	}
}
