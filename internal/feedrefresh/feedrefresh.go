// Package feedrefresh holds the fetch/refresh plumbing shared by the abuse.ch
// feed checkers (mbazaar, threatfox, urlhaus): the HTTP client, the bounded
// body reader, the empty/collapsed-feed guard, the HTTP status error and the
// background refresher loop. Per-feed parsing stays in each checker.
package feedrefresh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// COR-08: a refresh that returns HTTP 200 with zero entries, or with a tiny
// fraction of a large previous set, is a broken upstream response, not a
// real feed. Reject it so the last-good set and the warm-start cache stay.
const (
	minFeedForDropCheck = 1000
	maxFeedDropFactor   = 10
)

// ErrShrank is wrapped by CheckSize when a refresh is empty or collapsed.
var ErrShrank = errors.New("feed refresh rejected: empty or collapsed")

// ErrTooLarge matches (errors.Is) every *TooLargeError.
var ErrTooLarge = errors.New("feed exceeds byte limit")

// TooLargeError reports a feed body over the byte limit.
type TooLargeError struct{ Feed string }

func (e *TooLargeError) Error() string { return e.Feed + " feed exceeds byte limit" }

// Is makes errors.Is(err, ErrTooLarge) true for any feed.
func (e *TooLargeError) Is(target error) bool { return target == ErrTooLarge }

// StatusError reports a non-200 feed response.
type StatusError struct {
	Feed string
	Code int
}

func (e *StatusError) Error() string { return e.Feed + " feed HTTP " + strconv.Itoa(e.Code) }

// NewHTTPClient returns a client that never follows redirects.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ReadBody reads at most limit bytes of r; a longer body yields *TooLargeError.
func ReadBody(feed string, r io.Reader, limit int64) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: limit + 1}
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, &TooLargeError{Feed: feed}
	}
	return body, nil
}

// CheckSize rejects an empty refresh or a collapse to under a tenth of a large
// previous set.
func CheckSize(prev, next int) error {
	if next == 0 || (prev >= minFeedForDropCheck && next*maxFeedDropFactor < prev) {
		return fmt.Errorf("%w (%d -> %d entries)", ErrShrank, prev, next)
	}
	return nil
}

// Loop runs refresh immediately, then every interval, until stop closes or a
// refresh fails because ctx was cancelled (shutdown, not counted). Any other
// failure increments failures and is logged; the caller keeps its previous set.
func Loop(ctx context.Context, stop <-chan struct{}, interval time.Duration, feed string,
	refresh func(context.Context) error, failures *atomic.Uint64, logf func(string, ...any)) {
	if err := refresh(ctx); err != nil {
		if ctx.Err() != nil {
			return
		}
		failures.Add(1)
		logf("%s initial feed fetch failed: %v", feed, err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := refresh(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				failures.Add(1)
				logf("%s feed refresh failed (keeping previous set): %v", feed, err)
			}
		}
	}
}
