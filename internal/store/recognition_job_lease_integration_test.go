package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func recognitionLeasePrivatePostgres(t *testing.T) *DBStore {
	t.Helper()
	s := activityV3PrivatePostgres(t)
	if _, err := s.pg.db.Exec(`CREATE TABLE endpoint_entities(endpoint_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../migrations/postgres/060_single_node_high_load_v3.sql")
	if err != nil {
		t.Fatal(err)
	}
	schema := "CREATE TABLE IF NOT EXISTS endpoint_recognition_summary" + strings.Split(strings.Split(string(raw), "CREATE TABLE IF NOT EXISTS endpoint_recognition_summary")[1], "CREATE OR REPLACE FUNCTION enqueue_endpoint_recognition_job")[0]
	if _, err = s.pg.db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pg.db.Exec(`INSERT INTO endpoint_entities VALUES('endpoint'); INSERT INTO endpoint_recognition_jobs(endpoint_id) VALUES('endpoint')`); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRecognitionJobCompletionFencesReclaimedLeasePostgres(t *testing.T) {
	for _, mode := range []string{"new_owner_success", "new_owner_failure", "same_worker_success", "expired_success", "valid_success", "valid_failure"} {
		t.Run(mode, func(t *testing.T) {
			s := recognitionLeasePrivatePostgres(t)
			ctx := context.Background()
			old, found, err := s.claimRecognitionJob(ctx, "worker-a")
			if err != nil || !found {
				t.Fatalf("first claim: %v %v", found, err)
			}
			stale := strings.HasPrefix(mode, "new_owner") || mode == "same_worker_success" || mode == "expired_success"
			expectedOwner := ""
			expectedProcessed := int64(1)
			expectedAttempts := 0
			if stale {
				if _, err = s.pg.db.Exec(`UPDATE endpoint_recognition_jobs SET lease_until=now()-interval '1 second',dirty_generation=2`); err != nil {
					t.Fatal(err)
				}
				if mode != "expired_success" {
					worker := "worker-b"
					if mode == "same_worker_success" {
						worker = "worker-a"
					}
					if _, found, err = s.claimRecognitionJob(ctx, worker); err != nil || !found {
						t.Fatalf("reclaim: %v %v", found, err)
					}
				}
				if err = s.pg.db.QueryRow(`SELECT lease_owner FROM endpoint_recognition_jobs`).Scan(&expectedOwner); err != nil {
					t.Fatal(err)
				}
				expectedProcessed = 0
			}
			var failure error
			writeErr := s.withRecognitionLease(ctx, old, func(tx *sql.Tx) error {
				_, err := tx.Exec(`INSERT INTO endpoint_recognition_summary(endpoint_id,summary) VALUES('endpoint','{"writer":"old"}')`)
				return err
			})
			if stale && !errors.Is(writeErr, errRecognitionLeaseLost) {
				t.Fatalf("stale worker could write a profile: %v", writeErr)
			}
			if !stale && writeErr != nil {
				t.Fatal(writeErr)
			}
			var profiles int
			if err = s.pg.db.QueryRow(`SELECT count(*) FROM endpoint_recognition_summary`).Scan(&profiles); err != nil {
				t.Fatal(err)
			}
			if stale && profiles != 0 || !stale && profiles != 1 {
				t.Fatalf("profile ownership fence failed: stale=%v profiles=%d", stale, profiles)
			}
			if strings.HasSuffix(mode, "failure") {
				failure = errors.New("replay failure")
			}
			err = s.finishRecognitionJob(ctx, old, failure)
			if stale && err == nil {
				t.Error("stale completion was accepted")
			}
			if !stale && err != nil {
				t.Fatal(err)
			}
			if mode == "valid_failure" {
				expectedProcessed = 0
				expectedAttempts = 1
			}
			var owner, lastError string
			var processed int64
			var attempts int
			var notBefore time.Time
			if err = s.pg.db.QueryRow(`SELECT lease_owner,processed_generation,attempts,last_error,not_before FROM endpoint_recognition_jobs`).Scan(&owner, &processed, &attempts, &lastError, &notBefore); err != nil {
				t.Fatal(err)
			}
			if owner != expectedOwner || processed != expectedProcessed || attempts != expectedAttempts {
				t.Fatalf("old worker changed current lease or progress: owner=%s want=%s processed=%d want=%d attempts=%d want=%d", owner, expectedOwner, processed, expectedProcessed, attempts, expectedAttempts)
			}
			if mode == "valid_failure" {
				if lastError != "replay failure" || !notBefore.After(time.Now()) {
					t.Fatalf("valid failure lost retry/audit: error=%s retry=%s", lastError, notBefore)
				}
			} else if lastError != "" {
				t.Fatalf("stale failure poisoned new worker: %s", lastError)
			}
		})
	}
}

func TestRecognitionLeaseExpirationRollsBackProfilePostgres(t *testing.T) {
	s := recognitionLeasePrivatePostgres(t)
	ctx := context.Background()
	job, found, err := s.claimRecognitionJob(ctx, "writer")
	if err != nil || !found {
		t.Fatalf("claim: %v %v", found, err)
	}
	err = s.withRecognitionLease(ctx, job, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO endpoint_recognition_summary(endpoint_id,summary) VALUES('endpoint','{"writer":"expired"}')`); err != nil {
			return err
		}
		// Force the validity boundary after writing to verify transaction rollback.
		_, err := tx.Exec(`UPDATE endpoint_recognition_jobs SET lease_until=clock_timestamp()-interval '1 second'`)
		return err
	})
	if !errors.Is(err, errRecognitionLeaseLost) {
		t.Fatalf("expired write committed: %v", err)
	}
	var profiles int
	if err = s.pg.db.QueryRow(`SELECT count(*) FROM endpoint_recognition_summary`).Scan(&profiles); err != nil || profiles != 0 {
		t.Fatalf("expired profile persisted: %d %v", profiles, err)
	}
	var owner string
	if err = s.pg.db.QueryRow(`SELECT lease_owner FROM endpoint_recognition_jobs`).Scan(&owner); err != nil || owner != job.LeaseOwner {
		t.Fatalf("rollback changed lease owner: %s %v", owner, err)
	}
}
