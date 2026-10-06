package mailstrix

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	yara "github.com/hillu/go-yara/v4"
)

// ErrRuleCountDrop marks a verified bundle refused because its rule count fell
// sharply (or to zero) against the installed set. The current rules stay active.
var ErrRuleCountDrop = errors.New("rule count drop refused")

// minRuleCountPercent is the smallest accepted new/current ratio, in percent.
// Exactly this ratio is accepted; anything below is refused.
const minRuleCountPercent = 50

type allowCountDropKey struct{}

// WithAllowRuleCountDrop returns a context under which fetchRules installs a
// verified bundle even when its rule count dropped sharply or is zero. It is the
// operator opt-in (MAILSTRIX_RULES_ALLOW_COUNT_DROP / -allow-count-drop).
func WithAllowRuleCountDrop(ctx context.Context) context.Context {
	return context.WithValue(ctx, allowCountDropKey{}, true)
}

// rulesBundleCount loads a compiled bundle under the linked libyara and returns
// the number of rules it actually contains (never the manifest "rules" field).
func rulesBundleCount(path string) (int, error) {
	r, err := yara.LoadRules(path)
	if err != nil {
		return 0, err
	}
	if r == nil {
		return 0, nil
	}
	n := len(r.GetRules())
	r.Destroy()
	return n, nil
}

// checkRuleCountDrop decides whether a bundle with newCount rules may replace one
// with curCount rules. curCount <= 0 means no current set: only zero is refused.
// The drop test is integer-exact: new*100 < cur*50 refuses.
func checkRuleCountDrop(ctx context.Context, curCount, newCount int) error {
	if allowed, _ := ctx.Value(allowCountDropKey{}).(bool); allowed {
		return nil
	}
	if newCount <= 0 {
		return fmt.Errorf("%w: new bundle has 0 rules (set MAILSTRIX_RULES_ALLOW_COUNT_DROP to override)", ErrRuleCountDrop)
	}
	if curCount > 0 && newCount*100 < curCount*minRuleCountPercent {
		return fmt.Errorf("%w: new bundle has %d rules, current has %d (below %d%%; set MAILSTRIX_RULES_ALLOW_COUNT_DROP to override)", ErrRuleCountDrop, newCount, curCount, minRuleCountPercent)
	}
	return nil
}

// currentRuleCount returns the baseline the drop guard compares against. It
// counts the on-disk bundle whenever the file exists, independent of manifest
// trust (a missing or mismatched manifest must not make a large bundle look like
// a first install), and is floored by liveCount, the running scanner's count.
//
// Policy for an existing bundle that cannot be counted: log a warning and FAIL
// CLOSED (ErrRuleCountDrop) unless the operator allow-count-drop override is set,
// because a silent 0 would let any verified bundle replace it. The exception is
// a live scanner with rules (liveCount > 0): that count is an authoritative
// baseline, so the guard still applies against it and a corrupt cache can heal.
// An absent file is a genuine first install: baseline is liveCount (normally 0).
func currentRuleCount(ctx context.Context, cachePath string, liveCount int) (int, error) {
	cur := max(liveCount, 0)
	_, statErr := os.Stat(cachePath)
	if errors.Is(statErr, os.ErrNotExist) {
		return cur, nil
	}
	n, err := 0, statErr
	if statErr == nil {
		n, err = rulesBundleCount(cachePath)
	}
	if err == nil {
		return max(cur, n), nil
	}
	log.Printf("WARNING: existing rules bundle %s cannot be counted: %v", cachePath, err)
	if allowed, _ := ctx.Value(allowCountDropKey{}).(bool); allowed || cur > 0 {
		return cur, nil
	}
	return 0, fmt.Errorf("%w: existing bundle %s is unreadable (%w); set MAILSTRIX_RULES_ALLOW_COUNT_DROP to override", ErrRuleCountDrop, cachePath, err)
}
