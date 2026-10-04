package ci

import (
	"os"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func TestRulesPollingConfiguration(t *testing.T) {
	const key = "MAILSTRIX_RULES_POLL_INTERVAL"
	t.Run("bare default remains offline", func(t *testing.T) {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
		if got := mailstrix.LoadConfig().RulesPollInterval; got != 0 {
			t.Fatalf("bare default = %v, want disabled", got)
		}
	})
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"86400", 24 * time.Hour},
		{"0", 0},
		{"60", time.Minute},
		{"15m", -1},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(key, tc.value)
			got := mailstrix.LoadConfig().RulesPollInterval
			if tc.want < 0 {
				if got >= 0 {
					t.Fatalf("malformed interval became valid: %v", got)
				}
			} else if got != tc.want {
				t.Fatalf("interval = %v, want %v", got, tc.want)
			}
		})
	}
}
