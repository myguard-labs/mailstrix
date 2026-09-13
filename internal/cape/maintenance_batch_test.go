//go:build linux

package cape

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestMaintainBoundsActionableDecoding(t *testing.T) {
	const expectedBatchSize = 256
	ctx := context.Background()
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	for i := 0; i <= expectedBatchSize; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		j := Job{ID: id, Tenant: "alpha", State: Queued, Version: 1, Generation: "g1"}
		raw, err := encodeJob(j)
		if err != nil {
			t.Fatal(err)
		}
		if i == expectedBatchSize {
			raw = []byte("{")
		}
		if _, err = s.db.Exec(`INSERT INTO jobs(id,tenant,state,version,reserved,digest,generation,submission_policy,result_policy,document)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, id, j.Tenant, j.State, j.Version, 0, "", j.Generation, "", "", raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Maintain(ctx); err != nil {
		t.Fatalf("bounded pass decoded row beyond %d candidates: %v", expectedBatchSize, err)
	}
	if err := s.Maintain(ctx); err != ErrStoreUnavailable {
		t.Fatalf("malformed actionable row was not rejected on its batch: %v", err)
	}
}

func TestMarkCleanupDeadlinesBoundsActionableDecoding(t *testing.T) {
	const expectedBatchSize = 256
	ctx := context.Background()
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	for i := 0; i <= expectedBatchSize; i++ {
		id := fmt.Sprintf("10000000-0000-4000-8000-%012d", i)
		j := Job{ID: id, Tenant: "alpha", State: Completed, Version: 1, Generation: "g1"}
		raw, err := encodeJob(j)
		if err != nil {
			t.Fatal(err)
		}
		if i == expectedBatchSize {
			raw = []byte("{")
		}
		if _, err = s.db.Exec(`INSERT INTO jobs(id,tenant,state,version,reserved,digest,generation,submission_policy,result_policy,document)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, id, j.Tenant, j.State, j.Version, 0, "", j.Generation, "", "", raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.markCleanupDeadlines(ctx); err != nil {
		t.Fatalf("bounded cleanup-deadline pass decoded row beyond %d candidates: %v", expectedBatchSize, err)
	}
	if err := s.markCleanupDeadlines(ctx); err != ErrStoreUnavailable {
		t.Fatalf("malformed cleanup-deadline row was not rejected on its batch: %v", err)
	}
}

func TestActionableQueriesUseStateIndex(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	for _, query := range []string{
		"EXPLAIN QUERY PLAN SELECT document FROM jobs WHERE state IN (" + deadlineStates + ") AND id>'' ORDER BY id LIMIT 256",
		"EXPLAIN QUERY PLAN SELECT document FROM jobs WHERE state IN ('completed','cancelled','expired','failed') AND id>'' ORDER BY id LIMIT 256",
		"EXPLAIN QUERY PLAN SELECT document FROM jobs WHERE state IN ('queued','remote_pending','fetching','completed','failed','expired','cancelled') AND id>'' ORDER BY id LIMIT 256",
	} {
		rows, err := s.db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(detail)
		}
		rows.Close()
		if !strings.Contains(plan.String(), "jobs_state_id") {
			t.Fatalf("actionable query did not use jobs_state_id: %s", plan.String())
		}
	}
}
