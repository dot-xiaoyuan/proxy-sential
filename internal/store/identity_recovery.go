package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"proxy-sentinel/internal/normalized"
)

type IdentityRecoveryReport struct {
	FailedBatches          int      `json:"failed_batches"`
	RetainedRecords        int      `json:"retained_records"`
	UniqueEvents           int      `json:"unique_events"`
	AlreadyApplied         int      `json:"already_applied"`
	AlreadyImported        int      `json:"already_imported"`
	ImportedEvents         int      `json:"imported_events"`
	PendingIdentity        int      `json:"pending_identity"`
	RawExportPending       int      `json:"raw_export_pending"`
	MissingEvidenceBatches []string `json:"missing_evidence_batches"`
	InvalidEvents          int      `json:"invalid_events"`
	Complete               bool     `json:"complete"`
}

const identityRecoveryExportBudget = 50

// Recovery uses retained standard events, never changes a legacy failed batch to
// completed, and imports at most 25 records after the live inbox is idle. Every
// import has a deterministic ID and a durable lineage entry. Repeated recovery
// is safe even if the process died between acceptance and lineage recording.
func (s *PostgresStore) RecoverFailedIdentityBatches(ctx context.Context, source, sensor string, apply bool) (report IdentityRecoveryReport, err error) {
	report.MissingEvidenceBatches = []string{}
	seen := map[string]bool{}
	cursor := ""
	for {
		// Page by the existing primary key. Do not sort or retain every historical
		// payload in memory before recovery can make progress.
		rows, err := s.db.QueryContext(ctx, `SELECT batch_id,normalized_events FROM identity_ingest_batches WHERE batch_id>$3 AND protocol_version=1 AND status='failed' AND source=$1 AND sensor_id=$2 ORDER BY batch_id LIMIT 10`, source, sensor, cursor)
		if err != nil {
			return report, err
		}
		pageCount := 0
		unique := map[string]normalized.Event{}
		scopes := map[string]IdentityScope{}
		for rows.Next() {
			var id string
			var raw []byte
			if err = rows.Scan(&id, &raw); err != nil {
				break
			}
			cursor = id
			pageCount++
			report.FailedBatches++
			var events []normalized.Event
			if json.Unmarshal(raw, &events) != nil || len(events) == 0 {
				report.MissingEvidenceBatches = append(report.MissingEvidenceBatches, id)
				continue
			}
			report.RetainedRecords += len(events)
			for _, event := range events {
				scope := eventIdentityScope(event)
				if scope.Source != source || scope.SensorID != sensor || scope.CampusID == "" || scope.AccessDomain == "" || !validIdentityInboxEvent(scope, event) {
					report.InvalidEvents++
					continue
				}
				key := IdentityScopeKey(scope)
				combined := key + "\x00" + event.EventID
				if seen[combined] {
					continue
				}
				seen[combined] = true
				scopes[key] = scope
				unique[combined] = event
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return report, err
		}
		if pageCount == 0 {
			break
		}
		report.UniqueEvents += len(unique)
		for key, scope := range scopes {
			enabled := false
			if err = s.db.QueryRowContext(ctx, IdentityScopeStatusSQL(`SELECT enabled FROM identity_pipeline_scopes WHERE scope_key=$1`), key).Scan(&enabled); err != nil {
				return report, err
			}
			if !enabled {
				return report, fmt.Errorf("durable source must be enabled before history recovery")
			}
			events := []normalized.Event{}
			for combined, event := range unique {
				if combined == key+"\x00"+event.EventID {
					events = append(events, event)
				}
			}
			sort.Slice(events, func(i, j int) bool {
				if events[i].Timestamp != events[j].Timestamp {
					return events[i].Timestamp < events[j].Timestamp
				}
				return events[i].EventID < events[j].EventID
			})
			pending := []normalized.Event{}
			for start := 0; start < len(events); start += 500 {
				batch := events[start:min(start+500, len(events))]
				ids := []string{}
				for _, event := range batch {
					ids = append(ids, event.EventID)
				}
				found, e := s.db.QueryContext(ctx, `SELECT event_id,'applied' FROM identity_applied_events WHERE scope_key=$1 AND event_id=ANY($2::text[]) UNION ALL SELECT event_id,'imported' FROM identity_legacy_recovery_events WHERE scope_key=$1 AND event_id=ANY($2::text[])`, key, ids)
				if e != nil {
					return report, e
				}
				states := map[string]string{}
				for found.Next() {
					var id, state string
					if e = found.Scan(&id, &state); e != nil {
						break
					}
					if states[id] != "applied" {
						states[id] = state
					}
				}
				if e == nil {
					e = found.Err()
				}
				found.Close()
				if e != nil {
					return report, e
				}
				for _, event := range batch {
					switch states[event.EventID] {
					case "applied":
						report.AlreadyApplied++
					case "imported":
						report.AlreadyImported++
					default:
						pending = append(pending, event)
					}
				}
			}
			if !apply {
				continue
			}
			for start := 0; start < len(pending); start += 25 {
				for {
					var waiting, exportPending int64
					if err = s.db.QueryRowContext(ctx, IdentityScopeStatusSQL(`SELECT pending_records,export_pending_records FROM identity_pipeline_scopes WHERE scope_key=$1`), key).Scan(&waiting, &exportPending); err != nil {
						return report, err
					}
					if waiting == 0 && exportPending <= identityRecoveryExportBudget {
						break
					}
					select {
					case <-ctx.Done():
						return report, ctx.Err()
					case <-time.After(time.Second):
					}
				}
				batch := pending[start:min(start+25, len(pending))]
				raw, _ := json.Marshal(batch)
				sum := sha256.Sum256(raw)
				hash := hex.EncodeToString(sum[:])
				id := "identity-recovery-v2-" + hash
				if _, err = s.acceptIdentityBatch(ctx, id, hash, scope, batch, len(batch)); err != nil {
					return report, err
				}
				ids := []string{}
				for _, event := range batch {
					ids = append(ids, event.EventID)
				}
				_, err = s.db.ExecContext(ctx, `INSERT INTO identity_legacy_recovery_events(scope_key,event_id,import_batch_id) SELECT $1,unnest($2::text[]),$3 ON CONFLICT DO NOTHING`, key, ids, id)
				if err != nil {
					return report, err
				}
				report.ImportedEvents += len(batch)
				select {
				case <-ctx.Done():
					return report, ctx.Err()
				case <-time.After(time.Second):
				}
			}
		}
	}
	err = s.db.QueryRowContext(ctx, IdentityScopeStatusSQL(`SELECT COALESCE(sum(pending_records),0),COALESCE(sum(export_pending_records),0) FROM identity_pipeline_scopes WHERE source=$1 AND sensor_id=$2`), source, sensor).Scan(&report.PendingIdentity, &report.RawExportPending)
	report.Complete = err == nil && report.InvalidEvents == 0 && len(report.MissingEvidenceBatches) == 0 && report.AlreadyApplied == report.UniqueEvents && report.PendingIdentity == 0 && report.RawExportPending == 0
	return report, err
}
