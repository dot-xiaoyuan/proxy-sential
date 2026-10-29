package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
)

func TestIdentityDerivedReadyRetryCannotStarveBehindNewKeys(t *testing.T) {
	db := stdlib.OpenDB(*identityDerivedReadyTestConfig(t))
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Temporary names shadow the real tables only in this transaction/session.
	_, err = tx.ExecContext(ctx, identityDerivedRetryReplaySetupSQL)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(want string) {
		t.Helper()
		var batch, state string
		var ordinal, processed, records int
		var lease sql.NullTime
		var active, valid bool
		err := tx.QueryRowContext(ctx, identityDerivedReadyCandidateSQL, "sensor", 0).Scan(&batch, &ordinal, &state, &lease, &active, &processed, &records, &valid)
		if err != nil || batch != want || active || !valid {
			t.Fatalf("candidate=%q state=%q active=%v valid=%v, want=%q: %v", batch, state, active, valid, want, err)
		}
	}
	claim("retry")
	if _, err = tx.ExecContext(ctx, `UPDATE pg_temp.identity_derived_ready SET available_at=now()+interval '70 seconds' WHERE batch_id='retry'`); err != nil {
		t.Fatal(err)
	}
	claim("new-00")
}

const identityDerivedRetryReplaySetupSQL = `
CREATE TEMP TABLE identity_derived_ready(batch_id text,first_ordinal int,sensor_id text,priority int,available_at timestamptz,accepted_at timestamptz) ON COMMIT DROP;
CREATE TEMP TABLE identity_ingest_fragments(batch_id text,first_ordinal int,derived_state text,derived_lease_until timestamptz,record_count int) ON COMMIT DROP;
CREATE TEMP TABLE identity_ingest_batches(batch_id text,processed_offset int,protocol_version int,payload_format text,sensor_id text) ON COMMIT DROP;
INSERT INTO pg_temp.identity_derived_ready
 SELECT 'new-'||lpad(i::text,2,'0'),0,'sensor',0,'-infinity',now()-interval '1 day' FROM generate_series(0,39) i;
INSERT INTO pg_temp.identity_derived_ready VALUES
 ('retry',0,'sensor',0,now()-interval '1 minute',now()-interval '2 days'),
 ('leased',0,'sensor',0,now()+interval '1 minute',now()-interval '3 days');
INSERT INTO pg_temp.identity_ingest_fragments
 SELECT batch_id,0,CASE WHEN batch_id LIKE 'new-%' THEN 'pending' ELSE 'attempted' END,
 CASE WHEN batch_id LIKE 'new-%' THEN NULL ELSE available_at END,1 FROM pg_temp.identity_derived_ready;
INSERT INTO pg_temp.identity_ingest_batches
 SELECT batch_id,1,2,'fragments','sensor' FROM pg_temp.identity_derived_ready;
`
