package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
)

// RefreshPassiveRouterOwnership verifies one archived advertisement and changes only
// the current classification of the facts it actually produced. Historical decisions,
// source cursors and archive bodies are outside this operation.
func (s *DBStore) RefreshPassiveRouterOwnership(ctx context.Context, sensor, assessment string, ref StreamBodyRef, apply bool) (int64, error) {
	if sensor == "" || assessment == "" {
		return 0, errors.New("sensor and assessment are required")
	}
	event, found, err := s.ch.GetStreamEventByRef(ctx, ref)
	if err != nil {
		return 0, err
	}
	if !found || event.Source != "packet-sidecar" || event.SourceEventType != "ssdp" || event.Observer["sensor_id"] != sensor ||
		event.Subject["entity_role"] != "network_device" || event.EventID == "" || !strings.HasSuffix(ref.Key, ":"+event.EventID) {
		return 0, errors.New("archive did not verify the passive gateway event")
	}
	roles, err := evidence.AnalyzeRouters([]normalized.Event{event}, evidence.RouterOptions{AsOf: time.Now().UTC()})
	if err != nil {
		return 0, err
	}
	if len(roles.Assessments) != 1 || roles.Assessments[0].AssessmentID != assessment || roles.Assessments[0].Infrastructure {
		return 0, errors.New("original does not verify an unmarked network device for this assessment")
	}
	var ids []string
	var gateway bool
	for _, fact := range roles.Evidence {
		if fact.AssessmentID == assessment && !fact.Infrastructure && !fact.Expired {
			ids = append(ids, fact.EvidenceID)
			gateway = gateway || fact.RuleID == "ssdp-advertised-internet-gateway"
		}
	}
	if !gateway {
		return 0, errors.New("no current gateway advertisement in original")
	}
	original := roles.Assessments[0]
	if original.IP == "" || original.MAC == "" {
		return 0, errors.New("archived gateway is missing its outlet identity")
	}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return 0, err
	}
	tx, err := s.pg.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: !apply})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// The raw identity, time, complete event reference list and derived key must
	// all still agree. Newer, ambiguous, expired or explicitly owned facts stay intact.
	const matching = ` WHERE f.assessment_id=$1 AND f.evidence_id=ANY($2::text[]) AND f.source='packet-sidecar' AND f.source_family='ssdp'
 AND f.data->>'sensor_id'=$3 AND f.last_seen=$4 AND f.expires_at>now() AND f.data->>'infrastructure'='true'
 AND f.data->'event_ids'=jsonb_build_array($5::text) AND f.ip=$6::inet AND lower(f.mac)=$7
 AND EXISTS(SELECT 1 FROM shared_observation_mappings m JOIN account_identity_session_projection p
 ON p.source=m.identity_source AND p.sensor_id=m.identity_sensor_id AND p.campus_id=m.identity_campus_id AND p.access_domain=m.identity_access_domain
 WHERE m.active AND m.valid_from<=now() AND m.valid_until>now() AND m.sensor_id=$3 AND p.ip=host(f.ip) AND coalesce(p.document->>'ended_at','')=''
 AND regexp_replace(lower(p.document->>'mac'),'[^a-f0-9]','','g')=replace(lower(f.mac),':',''))`
	args := []any{assessment, ids, sensor, at, event.EventID, original.IP, strings.ToLower(original.MAC)}
	var n int64
	if apply {
		result, err := tx.ExecContext(ctx, `UPDATE router_evidence_facts f SET data=jsonb_set(f.data,'{infrastructure}','false')`+matching, args...)
		if err != nil {
			return 0, err
		}
		n, err = result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n > 0 {
			if err := rebuildRouterAssessment(ctx, tx, assessment, time.Now().UTC()); err != nil {
				return 0, err
			}
		}
	} else if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM router_evidence_facts f`+matching, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}
