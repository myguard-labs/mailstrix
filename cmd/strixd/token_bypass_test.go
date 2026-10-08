package main

import (
	"strings"
	"testing"
)

func TestTokenBypassWarnings(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		icapAddr     string
		clamdTCPAddr string
		wantCount    int
		wantContains []string // expected substrings in warnings
	}{
		{
			name:         "token set, both listeners",
			token:        "secret",
			icapAddr:     ":1344",
			clamdTCPAddr: "127.0.0.1:3310",
			wantCount:    2,
			wantContains: []string{":1344", "127.0.0.1:3310"},
		},
		{
			name:         "token set, ICAP only",
			token:        "secret",
			icapAddr:     ":1344",
			clamdTCPAddr: "",
			wantCount:    1,
			wantContains: []string{":1344"},
		},
		{
			name:         "token set, clamd TCP only",
			token:        "secret",
			icapAddr:     "",
			clamdTCPAddr: "127.0.0.1:3310",
			wantCount:    1,
			wantContains: []string{"127.0.0.1:3310"},
		},
		{
			name:         "token set, no listeners",
			token:        "secret",
			icapAddr:     "",
			clamdTCPAddr: "",
			wantCount:    0,
			wantContains: []string{},
		},
		{
			name:         "token empty, both listeners",
			token:        "",
			icapAddr:     ":1344",
			clamdTCPAddr: "127.0.0.1:3310",
			wantCount:    0,
			wantContains: []string{},
		},
		{
			name:         "token whitespace only, both listeners",
			token:        "   ",
			icapAddr:     ":1344",
			clamdTCPAddr: "127.0.0.1:3310",
			wantCount:    0,
			wantContains: []string{},
		},
		{
			name:         "token whitespace with newlines, both listeners",
			token:        " \n\t ",
			icapAddr:     ":1344",
			clamdTCPAddr: "127.0.0.1:3310",
			wantCount:    0,
			wantContains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := tokenBypassWarnings(tt.token, tt.icapAddr, tt.clamdTCPAddr)

			if len(warnings) != tt.wantCount {
				t.Errorf("got %d warnings, want %d; warnings: %v", len(warnings), tt.wantCount, warnings)
			}

			// Check that all expected substrings appear in the warnings
			for _, expected := range tt.wantContains {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, expected) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected substring %q not found in warnings: %v", expected, warnings)
				}
			}
		})
	}
}
