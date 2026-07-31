package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Guards the index coverage of the queries on the polling hot paths.
//
// The frontend polls the device list every 5s, traffic analysis every 60s, and the
// SMS thread list every 5s, so these run continuously rather than on demand. Each
// one previously filtered on a prefix of a composite index and then sorted the
// matched rows in memory, because the ORDER BY column sat behind other columns in
// the only available index.
//
// An index regression is silent -- nothing errors, results stay correct, the query
// just degrades as the table grows. Asserting on the query plan is the only cheap
// way to notice. These assertions are about index USE, not timings, so they are
// stable in CI.
//
// If one of these fails after a schema change, check the column order of the named
// index rather than deleting the assertion: GORM builds composite indexes from
// `priority` values spread across several struct tags, and getting one out of order
// silently produces an index the planner cannot use for the range or the sort.
func TestHotPathQueryPlansUseIndexes(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir + "/plan.db"); err != nil {
		t.Fatalf("init: %v", err)
	}

	cases := []struct {
		name string
		// why records what breaks in the UI if this plan degrades.
		why       string
		sql       string
		args      []any
		wantIndex string
	}{
		{
			name:      "latest traffic minute per device",
			why:       "device detail live rate; runs per selected device",
			sql:       `SELECT * FROM traffic_minute WHERE resource = ? AND tag = ? ORDER BY period_start DESC LIMIT 1`,
			args:      []any{"device", "dev1"},
			wantIndex: "idx_tm_res_tag_ps",
		},
		{
			name:      "hourly rollup range",
			why:       "dashboard traffic analysis, day range, every 60s",
			sql:       `SELECT period_start, tag, direction, traffic_bytes FROM traffic_hour WHERE resource = ? AND period_start >= ? AND period_start <= ? ORDER BY period_start ASC`,
			args:      []any{"iface", "2026-07-30 00:00:00", "2026-07-31 00:00:00"},
			wantIndex: "idx_th_res_ps",
		},
		{
			name:      "daily rollup range",
			why:       "dashboard traffic analysis, week/month ranges",
			sql:       `SELECT period_start, tag, direction, traffic_bytes FROM traffic_day WHERE resource = ? AND period_start >= ? AND period_start <= ? ORDER BY period_start ASC`,
			args:      []any{"iface", "2026-06-01 00:00:00", "2026-07-31 00:00:00"},
			wantIndex: "idx_td_res_ps",
		},
		{
			name:      "sms thread messages",
			why:       "SMS conversation pane; grows without bound per SIM",
			sql:       `SELECT * FROM sms WHERE iccid = ? AND peer = ? ORDER BY timestamp DESC LIMIT 50`,
			args:      []any{"8944", "+123"},
			wantIndex: "idx_sms_iccid_peer_ts",
		},
		{
			name:      "all sms for one SIM",
			why:       "GetSMSByICCID; distinct from the per-conversation query above",
			sql:       `SELECT * FROM sms WHERE iccid = ? ORDER BY timestamp DESC LIMIT 50`,
			args:      []any{"8944"},
			wantIndex: "idx_sms_iccid_ts",
		},
		{
			name:      "sms thread list",
			why:       "SMS page conversation list, every 5s",
			sql:       `SELECT * FROM sms_contacts WHERE iccid = ? ORDER BY last_timestamp DESC`,
			args:      []any{"8944"},
			wantIndex: "idx_sms_contact_iccid_last_ts",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := queryPlan(t, c.sql, c.args...)

			if !strings.Contains(plan, c.wantIndex) {
				t.Errorf("plan does not use %s (%s)\n  plan: %s", c.wantIndex, c.why, plan)
			}
			// The sort must be satisfied by the index, not by buffering rows.
			if strings.Contains(plan, "TEMP B-TREE") {
				t.Errorf("sorts in memory (%s)\n  plan: %s", c.why, plan)
			}
			// SEARCH means index-driven; a bare SCAN is a full table read.
			if strings.Contains(plan, "SCAN") && !strings.Contains(plan, "SEARCH") {
				t.Errorf("full table scan (%s)\n  plan: %s", c.why, plan)
			}
		})
	}
}

// The test above runs against an empty schema, where SQLite has no statistics and
// picks a plan from the index definitions alone. Production tables are neither empty
// nor un-analysed, and the planner can choose differently once sqlite_stat1 exists --
// so an empty-table assertion on its own would be a weak guarantee.
//
// This seeds a realistic table, runs ANALYZE, and re-checks the two hottest queries.
func TestHotPathPlansSurviveDataAndAnalyze(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir + "/analyzed.db"); err != nil {
		t.Fatalf("init: %v", err)
	}

	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	tx := DB.Begin()
	for i := 0; i < 5000; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		if err := tx.Exec(
			`INSERT INTO traffic_minute (period_start, resource, tag, direction, traffic_bytes, created_at, updated_at)
			 VALUES (?,?,?,?,?,?,?)`,
			ts, "device", fmt.Sprintf("dev%d", i%25), i%2 == 0, int64(i), ts, ts).Error; err != nil {
			tx.Rollback()
			t.Fatalf("seed traffic: %v", err)
		}
	}
	for i := 0; i < 5000; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		if err := tx.Exec(
			`INSERT INTO sms (message_id, imsi, iccid, peer, local_phone, sender, recipient, content, type, status, timestamp, created_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			fmt.Sprintf("m%d", i), "001010", fmt.Sprintf("894400%d", i%20),
			fmt.Sprintf("+1555%04d", i%150), "+1999", "a", "b", "x", 1+i%2, i%6, ts, ts).Error; err != nil {
			tx.Rollback()
			t.Fatalf("seed sms: %v", err)
		}
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := DB.Exec("ANALYZE").Error; err != nil {
		t.Fatalf("analyze: %v", err)
	}

	checks := []struct{ name, sql, wantIndex string; args []any }{
		{"latest traffic minute", `SELECT * FROM traffic_minute WHERE resource = ? AND tag = ? ORDER BY period_start DESC LIMIT 1`,
			"idx_tm_res_tag_ps", []any{"device", "dev1"}},
		{"sms thread", `SELECT * FROM sms WHERE iccid = ? AND peer = ? ORDER BY timestamp DESC LIMIT 50`,
			"idx_sms_iccid_peer_ts", []any{"8944000", "+15550001"}},
		{"all sms for one SIM", `SELECT * FROM sms WHERE iccid = ? ORDER BY timestamp DESC LIMIT 50`,
			"idx_sms_iccid_ts", []any{"8944000"}},
	}

	for _, c := range checks {
		plan := queryPlan(t, c.sql, c.args...)
		if !strings.Contains(plan, c.wantIndex) {
			t.Errorf("%s: expected %s once analysed, got: %s", c.name, c.wantIndex, plan)
		}
		if strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("%s: sorts in memory once analysed: %s", c.name, plan)
		}
	}
}

func queryPlan(t *testing.T, sql string, args ...any) string {
	t.Helper()
	rows, err := DB.Raw("EXPLAIN QUERY PLAN "+sql, args...).Rows()
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()

	var details []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate plan: %v", err)
	}
	return strings.Join(details, " | ")
}
