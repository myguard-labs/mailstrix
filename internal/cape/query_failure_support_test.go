//go:build linux

package cape

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"testing"
)

// This connector injects errors at the database/sql boundary without timing a
// cancellation or modifying the store's production query implementation.
type p10QueryConnector struct{ conn *p10QueryConn }

func (c p10QueryConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (c p10QueryConnector) Driver() driver.Driver                        { return p10QueryDriver{} }

type p10QueryDriver struct{}

func (p10QueryDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector required") }

type p10QueryConn struct {
	calls   int
	failAt  int
	cursors []string
	limits  []int64
}

func (*p10QueryConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*p10QueryConn) Close() error              { return nil }
func (*p10QueryConn) Begin() (driver.Tx, error) { return p10QueryTx{}, nil }

type p10QueryTx struct{}

func (p10QueryTx) Commit() error   { return nil }
func (p10QueryTx) Rollback() error { return nil }
func (c *p10QueryConn) QueryContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Rows, error) {
	c.calls++
	c.cursors = append(c.cursors, args[0].Value.(string))
	c.limits = append(c.limits, args[1].Value.(int64))
	if c.calls == c.failAt {
		return nil, errors.New("injected query failure")
	}
	return &p10QueryRows{job: c.calls == 2}, nil
}

type p10QueryRows struct{ job bool }

func (*p10QueryRows) Columns() []string { return []string{"document"} }
func (*p10QueryRows) Close() error      { return nil }
func (r *p10QueryRows) Next(v []driver.Value) error {
	if !r.job {
		return io.EOF
	}
	r.job = false
	v[0] = []byte(`{"ID":"a"}`)
	return nil
}

func TestP10MaintenanceInitialQueryFailure(t *testing.T) {
	for _, states := range []string{deadlineStates, cleanupStates, cleanupDeadlineStates} {
		for _, cursor := range []string{"", "z"} {
			t.Run(fmt.Sprintf("states=%s/cursor=%s", states, cursor), func(t *testing.T) {
				c := &p10QueryConn{failAt: 1}
				db := sql.OpenDB(p10QueryConnector{c})
				defer db.Close()
				tx, err := db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				jobs, next, err := nextMaintenanceBatch(tx, states, cursor)
				if jobs != nil || next != cursor || !errors.Is(err, ErrStoreUnavailable) {
					t.Fatalf("initial query failure must preserve cursor: jobs=%v next=%q want=%q error=%v", jobs, next, cursor, err)
				}
				if c.calls != 1 || c.cursors[0] != cursor || c.limits[0] != maintenanceBatchSize {
					t.Fatalf("initial query fixture: %+v", c)
				}
			})
		}
	}
}

func TestP10SchedulerWrapQueryFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%v", fail), func(t *testing.T) {
			c := &p10QueryConn{}
			if fail {
				c.failAt = 2
			}
			db := sql.OpenDB(p10QueryConnector{c})
			defer db.Close()
			s := &Store{db: db, schedulerCursor: "z"}
			jobs, err := s.schedulerJobs(context.Background())
			if fail {
				if jobs != nil || !errors.Is(err, ErrStoreUnavailable) || s.schedulerCursor != "z" {
					t.Fatalf("wrap query failure must preserve unavailable error and cursor: jobs=%v cursor=%q error=%v", jobs, s.schedulerCursor, err)
				}
			} else if err != nil || len(jobs) != 1 || jobs[0].ID != "a" || s.schedulerCursor != "a" {
				t.Fatalf("wrap query success: jobs=%v cursor=%q error=%v", jobs, s.schedulerCursor, err)
			}
			if c.calls != 2 || c.cursors[0] != "z" || c.cursors[1] != "" || c.limits[0] != maintenanceBatchSize || c.limits[1] != maintenanceBatchSize {
				t.Fatalf("wrap query fixture: %+v", c)
			}
		})
	}
}

// Query failures must not depend on cancellation winning the Run loop's race
// between maintenance and dispatch. Inject the initial read failure directly.
func TestP12SchedulerInitialQueryFailure(t *testing.T) {
	for _, mode := range []string{"store", "dispatch"} {
		t.Run(mode, func(t *testing.T) {
			conn := &p10QueryConn{failAt: 1}
			db := sql.OpenDB(p10QueryConnector{conn})
			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Error(err)
				}
			})
			store := &Store{db: db, schedulerCursor: "z"}
			if mode == "store" {
				jobs, err := store.schedulerJobs(context.Background())
				if jobs != nil || !errors.Is(err, ErrStoreUnavailable) {
					t.Fatalf("initial query must return unavailable without jobs: jobs=%v error=%v", jobs, err)
				}
			} else {
				q := &Scheduler{store: store, workers: 1}
				live := map[string]schedulerLive{}
				results := make(chan schedulerResult, 1)
				q.dispatch(context.Background(), live, results)
				if len(live) != 0 || len(results) != 0 {
					t.Fatal("initial query failure dispatched work")
				}
			}
			if store.schedulerCursor != "z" || conn.calls != 1 || len(conn.cursors) != 1 || conn.cursors[0] != "z" || len(conn.limits) != 1 || conn.limits[0] != maintenanceBatchSize {
				t.Fatal("initial query failure advanced cursor or retried the read")
			}
		})
	}
}

func TestP10MaintenanceQuerySuccess(t *testing.T) {
	for _, states := range []string{deadlineStates, cleanupStates, cleanupDeadlineStates} {
		for _, cursor := range []string{"", "z"} {
			t.Run(fmt.Sprintf("states=%s/cursor=%s", states, cursor), func(t *testing.T) {
				c := &p10QueryConn{}
				db := sql.OpenDB(p10QueryConnector{c})
				defer db.Close()
				tx, err := db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				jobs, next, err := nextMaintenanceBatch(tx, states, cursor)
				if err != nil {
					t.Fatal(err)
				}
				if cursor == "" {
					if len(jobs) != 0 || next != "" || c.calls != 1 {
						t.Fatalf("empty maintenance batch: jobs=%v next=%q calls=%d", jobs, next, c.calls)
					}
				} else if len(jobs) != 1 || jobs[0].ID != "a" || next != "a" || c.calls != 2 || c.cursors[1] != "" {
					t.Fatalf("maintenance wrap success: jobs=%v next=%q fixture=%+v", jobs, next, c)
				}
			})
		}
	}
}

// TestP10MaintenanceWrapQueryFailure pins the second query's error path without
// depending on whether a concurrent cancellation beats the cursor-wrap query.
func TestP10MaintenanceWrapQueryFailure(t *testing.T) {
	for _, states := range []string{deadlineStates, cleanupStates, cleanupDeadlineStates} {
		t.Run(states, func(t *testing.T) {
			c := &p10QueryConn{failAt: 2}
			db := sql.OpenDB(p10QueryConnector{c})
			defer db.Close()
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			jobs, next, err := nextMaintenanceBatch(tx, states, "z")
			if jobs != nil || next != "z" || !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("wrap query failure must preserve cursor and unavailable verdict: jobs=%v next=%q error=%v", jobs, next, err)
			}
			if c.calls != 2 || c.cursors[0] != "z" || c.cursors[1] != "" || c.limits[0] != maintenanceBatchSize || c.limits[1] != maintenanceBatchSize {
				t.Fatalf("maintenance wrap query fixture: %+v", c)
			}
		})
	}
}
