package mailstrix

import (
	"context"
	"io"

	"github.com/myguard-labs/mailstrix/internal/cape"
)

// capeStaticScan is used only by the staged manual attachment API. It preserves
// errors rather than using the fail-open static cache. Both native gates remain
// owned synchronously until Scan returns, even after cancellation.
// The per-call completion requirement rejects raw, child, or marker scan errors
// and exhausted budgets even when the ordinary mail scan recovers matches.
func (s *Server) capeStaticScan(ctx context.Context, _ string, input io.Reader) (string, error) {
	if ctx.Err() != nil || !s.acquireOn(ctx, s.admit) {
		return "", ErrCAPEUnavailable
	}
	defer func() { <-s.admit }()
	if ctx.Err() != nil {
		return "", ErrCAPEUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(input, cape.MaxAttachment+1))
	if err != nil || len(body) == 0 || len(body) > cape.MaxAttachment || ctx.Err() != nil {
		return "", ErrCAPEUnavailable
	}
	if !s.acquireOn(ctx, s.sem) {
		return "", ErrCAPEUnavailable
	}
	defer func() { <-s.sem }()
	if ctx.Err() != nil {
		return "", ErrCAPEUnavailable
	}
	meta := ScanMeta{Effort: s.cfg.EffortMax, RawKey: streamDedupKey(body), requireComplete: true}
	matches, err := s.dispatch(body, meta)
	if err != nil || ctx.Err() != nil {
		return "", ErrCAPEUnavailable
	}
	for _, match := range matches {
		if !matchIsLogOnly(match) {
			return "malicious", nil
		}
	}
	return "unknown", nil
}
