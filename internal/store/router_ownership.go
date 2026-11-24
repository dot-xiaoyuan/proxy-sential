package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
)

// RefreshPassiveRouterOwnership verifies archived advertisements and changes only
// the current classification of the facts it actually produced. Historical decisions,
// source cursors and archive bodies are outside this operation.
func (s *DBStore) RefreshPassiveRouterOwnership(ctx context.Context, sensor, assessment string, refs []StreamBodyRef, apply bool) (int64, error) {
	if sensor == "" || assessment == "" {
		return 0, errors.New("sensor and assessment are required")
	}
	if len(refs) == 0 || len(refs) > 20 {
		return 0, errors.New("one to twenty archive references are required")
	}
	bodies, err := s.ch.GetStreamEventsByRefs(ctx, refs)
	if err != nil {
		return 0, err
	}
	times := make(map[string]time.Time, len(refs))
	var originals []normalized.Event
	var ip, mac, vlan string
	for i, ref := range refs {
		event, found := bodies[ref]
		if !found || ref.Scope != refs[0].Scope || evidence.RouterInfrastructureDeclared(event) ||
			event.Source != "packet-sidecar" || event.SourceEventType != "ssdp" || event.Observer["sensor_id"] != sensor ||
			event.Subject["entity_role"] != "network_device" || event.EventID == "" || !strings.HasSuffix(ref.Key, ":"+event.EventID) {
			return 0, errors.New("archive did not verify the passive gateway event")
		}
		at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil {
			return 0, err
		}
		if _, duplicate := times[event.EventID]; duplicate {
			return 0, errors.New("duplicate archive event")
		}
		eventIP, _ := event.Subject["ip"].(string)
		eventMAC, _ := event.Subject["mac"].(string)
		tag := fmt.Sprint(event.Payload["vlan"])
		if i == 0 {
			ip, mac, vlan = eventIP, strings.ToLower(eventMAC), tag
		}
		if ip == "" || mac == "" || eventIP != ip || !strings.EqualFold(eventMAC, mac) || tag != vlan {
			return 0, errors.New("archived sources have different outlet identities")
		}
		times[event.EventID] = at.UTC()
		originals = append(originals, event)
	}
	roles, err := evidence.AnalyzeRouters(originals, evidence.RouterOptions{AsOf: time.Now().UTC()})
	if err != nil {
		return 0, err
	}
	if len(roles.Assessments) != 1 || roles.Assessments[0].AssessmentID != assessment || roles.Assessments[0].Infrastructure {
		return 0, errors.New("originals do not verify an unmarked network device for this assessment")
	}
	gateway := false
	for _, fact := range roles.Evidence {
		if fact.RuleID == "ssdp-advertised-internet-gateway" && !fact.Expired {
			gateway = true
		}
	}
	if !gateway {
		return 0, errors.New("no current gateway advertisement in originals")
	}
	sourceTimes, err := json.Marshal(times)
	if err != nil {
		return 0, err
	}
	tx, err := s.pg.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: !apply})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// The raw identity, time and complete event reference list must
	// all still agree. A list at its storage cap may have omitted contributors.
	const matching = ` WHERE f.assessment_id=$1 AND f.source='packet-sidecar' AND f.source_family='ssdp'
 AND f.data->>'source_event_type'='ssdp' AND f.data->>'sensor_id'=$2 AND f.expires_at>now() AND f.data->>'infrastructure'='true'
 AND f.ip=$4::inet AND lower(f.mac)=$5 AND jsonb_array_length(f.data->'event_ids') BETWEEN 1 AND 19
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(f.data->'event_ids') id WHERE NOT ($3::jsonb ? id))
 AND f.last_seen=(SELECT max(stamp::timestamptz) FROM jsonb_each_text($3::jsonb) t(id,stamp) WHERE f.data->'event_ids' ? id)
 AND EXISTS(SELECT 1 FROM shared_observation_mappings m JOIN account_identity_session_projection p
 ON p.source=m.identity_source AND p.sensor_id=m.identity_sensor_id AND p.campus_id=m.identity_campus_id AND p.access_domain=m.identity_access_domain
 WHERE m.active AND m.valid_from<=now() AND m.valid_until>now() AND m.sensor_id=$2 AND p.ip=host(f.ip) AND coalesce(p.document->>'ended_at','')=''
 AND regexp_replace(lower(p.document->>'mac'),'[^a-f0-9]','','g')=replace(lower(f.mac),':',''))`
	args := []any{assessment, sensor, string(sourceTimes), ip, mac}
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
