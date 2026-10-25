package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/sharedaccess"
	"time"
)

type sharedArchiveBundle struct {
	Decision        sharedaccess.ObservationDecision `json:"decision"`
	Assessment      sharedaccess.BehaviorAssessment  `json:"assessment"`
	RawEvents       []sharedObservationEvent         `json:"raw_events"`
	RawAssociations []sharedAssociationEvent         `json:"raw_associations,omitempty"`
	RawRefs         []StreamBodyRef                  `json:"raw_refs,omitempty"`
}

// Archive one committed result at a time, behind real-time work. Reading the
// content back and checking its hash is mandatory before removing hot copies.
// Archives deliberately have no destructive TTL: case references remain safe.
func (s *DBStore) ArchiveSharedObservation(ctx context.Context) (bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	maintenance, err := tx.ExecContext(ctx, `UPDATE shared_observation_executions SET state='expired',document=jsonb_set(document,'{state}','"expired"') WHERE execution_id IN (
 SELECT execution_id FROM shared_observation_executions WHERE state='recorded' AND expires_at<=now()
 AND NOT EXISTS(SELECT 1 FROM shared_observation_jobs j WHERE revision>completed_revision AND NOT expired AND canceled_epoch=''
  AND generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
  AND dirty_since<now()-interval '5 seconds')
 ORDER BY expires_at,execution_id FOR UPDATE SKIP LOCKED LIMIT 500)`)
	if err != nil {
		return false, err
	}
	maintained, err := maintenance.RowsAffected()
	if err != nil {
		return false, err
	}
	var raw, assessment []byte
	var received time.Time
	err = tx.QueryRowContext(ctx, `SELECT d.document,o.observation,d.first_received_at FROM policy_decision_records d JOIN shared_behavior_observations o ON o.observation_id=d.observation_id
 WHERE d.trigger_type='shared_access' AND d.first_received_at<now()-interval '30 days'
 AND NOT EXISTS(SELECT 1 FROM shared_observation_jobs j WHERE revision>completed_revision AND NOT expired AND canceled_epoch=''
  AND generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
  AND dirty_since<now()-interval '5 seconds')
 ORDER BY d.first_received_at,d.decision_id FOR UPDATE OF d SKIP LOCKED LIMIT 1`).Scan(&raw, &assessment, &received)
	if err == sql.ErrNoRows {
		return maintained > 0, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	var bundle sharedArchiveBundle
	if err = json.Unmarshal(raw, &bundle.Decision); err != nil {
		return true, err
	}
	if err = json.Unmarshal(assessment, &bundle.Assessment); err != nil {
		return true, err
	}
	d := bundle.Decision
	w := d.Evidence
	var data []byte
	verifiedEvents := []sharedObservationEvent{}
	verifiedAssociations := []sharedAssociationEvent{}
	if epoch := w.SourceEpochs["handshake-sidecar"]; epoch != "" {
		scopeID := w.SourceScopes["handshake-sidecar"]
		if scopeID == "" {
			return true, fmt.Errorf("shared archive missing handshake source scope")
		}
		var refs []StreamSharedSignalRef
		verifiedEvents, _, refs, err = s.readStreamSharedRowsWithRefs(ctx, SharedObservationScope{w.SensorID, w.CampusID, w.AccessDomain, w.IP}, scopeID, "handshake-sidecar", epoch, w.IP, w.From.Add(-time.Minute), w.To.Add(time.Minute))
		if err != nil {
			return true, err
		}
		for _, ref := range refs {
			bundle.RawRefs = append(bundle.RawRefs, ref.Body)
		}
	} else {
		query := fmt.Sprintf(`SELECT formatDateTime(min(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS timestamp,event_id,source,collector_instance_id,subject_ip,payload_json,uniqExact(payload_json) AS payload_versions FROM shared_observation_events_v2
 PREWHERE sensor_id=%s AND campus_id=%s AND access_domain=%s AND subject_ip IN ('',%s)
 AND timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<=parseDateTime64BestEffort(%s,6)
 GROUP BY event_id,source,collector_instance_id,subject_ip,payload_json ORDER BY event_id,payload_json LIMIT 2001 SETTINGS prefer_column_name_to_alias=1,max_threads=1,max_memory_usage=134217728,max_execution_time=2 FORMAT JSONEachRow`, chQuote(w.SensorID), chQuote(w.CampusID), chQuote(w.AccessDomain), chQuote(w.IP), chQuote(w.From.Add(-time.Minute).Format(time.RFC3339Nano)), chQuote(w.To.Add(time.Minute).Format(time.RFC3339Nano)))
		data, err = s.ch.query(ctx, query)
		if err != nil {
			return true, err
		}
		if err = decodeJSONEachRow(data, &bundle.RawEvents); err != nil {
			return true, err
		}
		if len(bundle.RawEvents) > 2000 {
			return true, fmt.Errorf("archive raw evidence bound exceeded")
		}
		verifiedEvents = bundle.RawEvents
	}
	if w.GatewayMAC != "" {
		if epoch := w.SourceEpochs["packet-sidecar"]; epoch != "" {
			scopeID := w.SourceScopes["packet-sidecar"]
			if scopeID == "" {
				return true, fmt.Errorf("shared archive missing packet source scope")
			}
			var refs []StreamSharedSignalRef
			_, verifiedAssociations, refs, err = s.readStreamSharedRowsWithRefs(ctx, SharedObservationScope{w.SensorID, w.CampusID, w.AccessDomain, w.IP}, scopeID, "packet-sidecar", epoch, w.GatewayMAC, w.From.Add(-time.Minute), w.To.Add(time.Minute))
			if err != nil {
				return true, err
			}
			for _, ref := range refs {
				bundle.RawRefs = append(bundle.RawRefs, ref.Body)
			}
		} else {
			bundle.RawAssociations, err = s.sharedAssociationRowsLegacy(ctx, SharedObservationScope{w.SensorID, w.CampusID, w.AccessDomain, w.IP}, w.GatewayMAC, w.From.Add(-time.Minute), w.To.Add(time.Minute), true)
			if err != nil {
				return true, err
			}
			verifiedAssociations = bundle.RawAssociations
		}
	}
	found := map[string]bool{}
	for _, event := range verifiedEvents {
		found[event.Source+"/"+event.Instance+"/"+event.EventID] = true
	}
	for _, event := range verifiedAssociations {
		found[event.Source+"/"+event.Instance+"/"+event.EventID] = true
	}
	for _, ref := range w.Records {
		if !found[ref.Source+"/"+ref.InstanceID+"/"+ref.EventID] {
			return true, fmt.Errorf("archive missing original event %s", ref.EventID)
		}
	}
	for _, fact := range w.CoverageFacts {
		if !found[fact.Source+"/"+fact.Instance+"/"+fact.EventID] {
			return true, fmt.Errorf("archive missing coverage event %s", fact.EventID)
		}
	}
	document, err := json.Marshal(bundle)
	if err != nil {
		return true, err
	}
	if len(document) > 8<<20 {
		return true, fmt.Errorf("archive bundle exceeds 8 MiB")
	}
	sum := sha256.Sum256(document)
	hash := hex.EncodeToString(sum[:])
	row, _ := json.Marshal(map[string]any{"observation_id": d.ObservationID, "decision_id": d.DecisionID, "first_received_at": received.UTC().Format("2006-01-02 15:04:05.000000"), "content_hash": hash, "document": string(document)})
	if err = s.ch.exec(ctx, "INSERT INTO shared_observation_archive_v1 FORMAT JSONEachRow\n"+string(row)); err != nil {
		return true, err
	}
	data, err = s.ch.query(ctx, `SELECT document FROM shared_observation_archive_v1 WHERE observation_id=`+chQuote(d.ObservationID)+` AND decision_id=`+chQuote(d.DecisionID)+` AND content_hash=`+chQuote(hash)+` LIMIT 1 SETTINGS max_threads=1,max_execution_time=2 FORMAT JSONEachRow`)
	if err != nil {
		return true, err
	}
	var verified []struct {
		Document string `json:"document"`
	}
	if err = decodeJSONEachRow(data, &verified); err != nil {
		return true, err
	}
	if len(verified) != 1 {
		return true, fmt.Errorf("archive verification missing")
	}
	check := sha256.Sum256([]byte(verified[0].Document))
	if check != sum {
		return true, fmt.Errorf("archive content checksum mismatch")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_archive_receipts(decision_id,observation_id,content_hash,first_received_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, d.DecisionID, d.ObservationID, hash, received)
	if err != nil {
		return true, err
	}
	// Case snapshots are independent retained copies; the archive is also kept.
	_, err = tx.ExecContext(ctx, `DELETE FROM policy_decision_records WHERE decision_id=$1`, d.DecisionID)
	if err != nil {
		return true, err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM shared_observation_executions WHERE evidence_version=$1 AND state='expired' AND NOT EXISTS(SELECT 1 FROM policy_decision_records WHERE evidence_version=$1)`, d.EvidenceVersion)
	if err != nil {
		return true, err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM shared_behavior_observations WHERE observation_id=$1 AND NOT current AND NOT EXISTS(SELECT 1 FROM policy_decision_records WHERE observation_id=$1) AND NOT EXISTS(SELECT 1 FROM risk_case_evidence_snapshots WHERE evidence::text LIKE '%'||$1||'%')`, d.ObservationID)
	if err != nil {
		return true, err
	}
	return true, tx.Commit()
}

func (s *DBStore) archivedSharedBehavior(ctx context.Context, id string) (SharedBehaviorDetail, bool, error) {
	data, err := s.ch.query(ctx, `SELECT document FROM shared_observation_archive_v1 WHERE observation_id=`+chQuote(id)+` ORDER BY archived_at DESC LIMIT 1 SETTINGS max_threads=1,max_execution_time=2 FORMAT JSONEachRow`)
	if err != nil {
		return SharedBehaviorDetail{}, false, err
	}
	var rows []struct {
		Document string `json:"document"`
	}
	if err = decodeJSONEachRow(data, &rows); err != nil || len(rows) == 0 {
		return SharedBehaviorDetail{}, false, err
	}
	var bundle sharedArchiveBundle
	if err = json.Unmarshal([]byte(rows[0].Document), &bundle); err != nil {
		return SharedBehaviorDetail{}, false, err
	}
	bundle.Assessment.Current = false
	return SharedBehaviorDetail{BehaviorAssessment: bundle.Assessment, History: []SharedBehaviorHistory{}}, true, nil
}
