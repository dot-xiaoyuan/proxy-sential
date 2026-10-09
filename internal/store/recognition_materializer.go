package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type recognitionJob struct {
	EndpointID      string
	DirtyGeneration int64
	Attempts        int
	LeaseOwner      string
}

var errRecognitionLeaseLost = errors.New("endpoint recognition lease is no longer current")

func (s *DBStore) withRecognitionLease(ctx context.Context, job recognitionJob, write func(*sql.Tx) error) error {
	if job.LeaseOwner == "" {
		return errRecognitionLeaseLost
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current bool
	err = tx.QueryRowContext(ctx, `SELECT lease_owner=$2 AND lease_until>clock_timestamp()
FROM endpoint_recognition_jobs WHERE endpoint_id=$1 FOR UPDATE`, job.EndpointID, job.LeaseOwner).Scan(&current)
	if err == sql.ErrNoRows || err == nil && !current {
		return errRecognitionLeaseLost
	}
	if err != nil {
		return err
	}
	if err = write(tx); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT lease_until>clock_timestamp() FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, job.EndpointID).Scan(&current); err != nil {
		return err
	}
	if !current {
		return errRecognitionLeaseLost
	}
	return tx.Commit()
}

func (s *DBStore) claimRecognitionJob(ctx context.Context, worker string) (recognitionJob, bool, error) {
	// Each claim needs its own token, including retries by the same worker.
	owner := worker + ":" + appToken()
	row := s.pg.db.QueryRowContext(ctx, `WITH picked AS (
 SELECT endpoint_id FROM endpoint_recognition_jobs
 WHERE processed_generation<dirty_generation AND not_before<=now() AND lease_until<now()
 ORDER BY updated_at,endpoint_id FOR UPDATE SKIP LOCKED LIMIT 1)
UPDATE endpoint_recognition_jobs j SET lease_owner=$1,lease_until=now()+interval '1 minute',updated_at=now()
FROM picked p WHERE j.endpoint_id=p.endpoint_id
RETURNING j.endpoint_id,j.dirty_generation,j.attempts,j.lease_owner`, owner)
	var job recognitionJob
	if err := row.Scan(&job.EndpointID, &job.DirtyGeneration, &job.Attempts, &job.LeaseOwner); err != nil {
		if err == sql.ErrNoRows {
			return recognitionJob{}, false, nil
		}
		return recognitionJob{}, false, err
	}
	return job, true, nil
}

func recognitionTimestamp(raw string) any {
	if raw == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil
	}
	return parsed
}

func (s *DBStore) materializeRecognition(ctx context.Context, job recognitionJob) error {
	profile, found, err := s.pg.GetEndpointIdentity(ctx, job.EndpointID, Query{Limit: 200})
	if err != nil {
		return err
	}
	if !found || profile.Recognition == nil {
		return s.withRecognitionLease(ctx, job, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM endpoint_recognition_summary WHERE endpoint_id=$1`, job.EndpointID)
			return err
		})
	}
	item := profile.Recognition
	filterBrand, filterOSFamily := deviceFilterValues(*item)
	deviceName := ""
	if item.DeviceName != nil {
		deviceName = item.DeviceName.Value
	}
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	listRaw, err := json.Marshal(ProjectDeviceInventoryListItem(*item))
	if err != nil {
		return err
	}
	evidenceCount := len(item.RecognitionEvidence) + len(profile.EcosystemEvidence)
	return s.withRecognitionLease(ctx, job, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO endpoint_recognition_summary(
 endpoint_id,brand,model,os_family,role,confidence,conflict,evidence_count,rule_version,summary,first_seen,last_seen,
 primary_mac,current_ip,current_account,current_access_id,device_name,filter_brand,filter_os_family,ecosystem_hint,list_item,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,now())
ON CONFLICT(endpoint_id) DO UPDATE SET brand=EXCLUDED.brand,model=EXCLUDED.model,os_family=EXCLUDED.os_family,
 role=EXCLUDED.role,confidence=EXCLUDED.confidence,conflict=EXCLUDED.conflict,evidence_count=EXCLUDED.evidence_count,
 rule_version=EXCLUDED.rule_version,summary=EXCLUDED.summary,first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,
 primary_mac=EXCLUDED.primary_mac,current_ip=EXCLUDED.current_ip,current_account=EXCLUDED.current_account,
 current_access_id=EXCLUDED.current_access_id,device_name=EXCLUDED.device_name,filter_brand=EXCLUDED.filter_brand,
 filter_os_family=EXCLUDED.filter_os_family,ecosystem_hint=EXCLUDED.ecosystem_hint,list_item=EXCLUDED.list_item,updated_at=now()`,
			job.EndpointID, item.Brand, item.Model, item.OSFamily, item.DeviceType, item.RecognitionConfidence,
			item.RecognitionConflict, evidenceCount, item.FingerprintVersion, raw, recognitionTimestamp(item.FirstSeen), recognitionTimestamp(item.LastSeen),
			item.PrimaryMAC, item.CurrentIP, item.CurrentAccount, item.CurrentAccessID, deviceName, filterBrand, filterOSFamily, item.EcosystemHint, listRaw)
		return err
	})
}

func (s *DBStore) finishRecognitionJob(ctx context.Context, job recognitionJob, runErr error) error {
	if job.LeaseOwner == "" {
		return errRecognitionLeaseLost
	}
	var result sql.Result
	var err error
	if runErr == nil {
		result, err = s.pg.db.ExecContext(ctx, `UPDATE endpoint_recognition_jobs SET processed_generation=GREATEST(processed_generation,$2),
 attempts=0,lease_owner='',lease_until='-infinity',last_error='',updated_at=now()
 WHERE endpoint_id=$1 AND lease_owner=$3 AND lease_until>clock_timestamp()`, job.EndpointID, job.DirtyGeneration, job.LeaseOwner)
	} else {
		attempts := job.Attempts + 1
		delay := time.Second * time.Duration(1<<min(attempts, 8))
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		result, err = s.pg.db.ExecContext(ctx, `UPDATE endpoint_recognition_jobs SET attempts=$2,lease_owner='',lease_until='-infinity',
 last_error=$3,not_before=now()+$4::interval,updated_at=now()
 WHERE endpoint_id=$1 AND lease_owner=$5 AND lease_until>clock_timestamp()`, job.EndpointID, attempts, runErr.Error(), delay.String(), job.LeaseOwner)
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errRecognitionLeaseLost
	}
	return nil
}

func (s *DBStore) RunRecognitionMaterializer(ctx context.Context) {
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		s.runSharedDeviceProfileMaterializer(ctx)
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		s.runSharedBehaviorMaterializer(ctx, s.pg.sensorID)
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		s.runRouterRecognitionMaterializer(ctx, s.pg.sensorID)
	}()
	for index := 0; index < 4; index++ {
		workers.Add(1)
		go func(workerIndex int) {
			defer workers.Done()
			s.runRecognitionMaterializerWorker(ctx, fmt.Sprintf("recognition-%d-%d", os.Getpid(), workerIndex))
		}(index)
	}
	workers.Wait()
}

func (s *DBStore) runSharedBehaviorMaterializer(ctx context.Context, sensorID string) {
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		_, err := s.materializeSharedBehavior(workCtx, sensorID, time.Now().UTC())
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "shared behavior materialize failed: %v\n", err)
			if reportErr := s.recordSharedBehaviorFailure(ctx, err); reportErr != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "shared behavior failure status write failed: %v\n", reportErr)
			}
		}
		cancel()
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// A failed work deadline must not suppress diagnostic writes, but these writes
// must remain bounded and cancel with the service so recovery can continue.
func (s *DBStore) recordSharedBehaviorFailure(parent context.Context, runErr error) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	state, _ := json.Marshal(map[string]any{"error": runErr.Error()})
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('shared-behavior',$1,now()) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, state)
	return err
}

func (s *DBStore) runRecognitionMaterializerWorker(ctx context.Context, worker string) {
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		job, found, err := s.claimRecognitionJob(workCtx, worker)
		if err == nil && found {
			err = s.materializeRecognition(workCtx, job)
			if err != nil {
				fmt.Fprintf(os.Stderr, "recognition materialize failed for %s: %v\n", job.EndpointID, err)
			}
			finishCtx, finishCancel := context.WithTimeout(ctx, 5*time.Second)
			if finishErr := s.finishRecognitionJob(finishCtx, job, err); finishErr != nil {
				fmt.Fprintf(os.Stderr, "recognition completion failed for %s: %v\n", job.EndpointID, finishErr)
				err = finishErr
			}
			if err == nil {
				_, _ = s.pg.db.ExecContext(finishCtx, `INSERT INTO read_model_runtime_state(name,state,updated_at)
VALUES('endpoint-recognition',jsonb_build_object('as_of',now()::text),now())
ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`)
			}
			finishCancel()
		}
		cancel()
		delay := time.Second
		if !found {
			delay = 5 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
