package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sharedIngestBatchKey struct{}

// The durable batch start is a conservative latency origin across retries.
func WithSharedIngestBatch(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sharedIngestBatchKey{}, id)
}

func (s *DBStore) EnableSharedObservation() { s.pg.sharedObservationEnabled = true }

func SharedObservationEnabled() bool {
	enabled, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_SHARED_OBSERVATION_ENABLED")))
	return enabled
}

type SharedObservationScope struct {
	SensorID     string `json:"sensor_id"`
	CampusID     string `json:"campus_id"`
	AccessDomain string `json:"access_domain"`
	IP           string `json:"ip"`
}
type SharedObservationReader interface {
	ReadSharedObservation(context.Context, SharedObservationScope, sharedaccess.Config, time.Time) (sharedaccess.Window, sharedaccess.BehaviorAssessment, error)
	SharedIdentitySessions(context.Context, sharedaccess.IdentityMapping, string, time.Time, time.Time, int) ([]policy.Session, error)
}

func (s *DBStore) enqueueSharedObservations(ctx context.Context, events []normalized.Event) error {
	if err := s.recordSharedCaptureProgress(ctx, events); err != nil {
		return err
	}
	if err := s.enqueueSharedGateways(ctx, events); err != nil {
		return err
	}
	type pending struct {
		SharedObservationScope
		ID string    `json:"id"`
		At time.Time `json:"at"`
	}
	jobs := map[string]pending{}
	for _, e := range events {
		if e.Source != "handshake-sidecar" || e.SourceEventType != "handshake" {
			continue
		}
		v := SharedObservationScope{stringFromMap(e.Observer, "sensor_id"), stringFromMap(e.Payload, "campus_id"), stringFromMap(e.Payload, "access_domain"), stringFromMap(e.Subject, "ip")}
		if v.CampusID == "" {
			v.CampusID = stringFromMap(e.Subject, "campus_id")
		}
		if v.SensorID == "" || v.IP == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			return err
		}
		id := policy.StableID(v.SensorID, v.CampusID, v.AccessDomain, v.IP)
		if old, ok := jobs[id]; !ok || at.After(old.At) {
			jobs[id] = pending{v, id, at}
		}
	}
	if len(jobs) == 0 {
		return nil
	}
	items := []pending{}
	for _, p := range jobs {
		items = append(items, p)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	raw, err := json.Marshal(items)
	if err != nil {
		return err
	}
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO shared_observation_jobs(job_id,sensor_id,campus_id,access_domain,ip,last_event_at,first_received_at,dirty_since)
 SELECT id,sensor_id,campus_id,access_domain,ip::inet,at,COALESCE((SELECT started_at FROM ingest_batches WHERE batch_id=$2),now()),COALESCE((SELECT started_at FROM ingest_batches WHERE batch_id=$2),now()) FROM jsonb_to_recordset($1::jsonb) r(id text,sensor_id text,campus_id text,access_domain text,ip text,at timestamptz) ORDER BY id
 ON CONFLICT(job_id) DO UPDATE SET revision=shared_observation_jobs.revision+1,last_event_at=GREATEST(shared_observation_jobs.last_event_at,EXCLUDED.last_event_at),last_received_at=now(),
 dirty_since=CASE WHEN shared_observation_jobs.revision=shared_observation_jobs.completed_revision THEN EXCLUDED.dirty_since ELSE LEAST(shared_observation_jobs.dirty_since,EXCLUDED.dirty_since) END,
 next_attempt_at=LEAST(shared_observation_jobs.next_attempt_at,now()),expired=false`, raw, ctx.Value(sharedIngestBatchKey{}))
	return err
}

type sharedObservationEvent struct {
	PayloadVersions int    `json:"payload_versions"`
	Timestamp       string `json:"timestamp"`
	EventID         string `json:"event_id"`
	Source          string `json:"source"`
	Instance        string `json:"collector_instance_id"`
	IP              string `json:"subject_ip"`
	Payload         string `json:"payload_json"`
}

func (s *DBStore) ReadSharedObservation(ctx context.Context, scope SharedObservationScope, cfg sharedaccess.Config, now time.Time) (sharedaccess.Window, sharedaccess.BehaviorAssessment, error) {
	// Raw column names must win over output aliases in PREWHERE and aggregates.
	// ClickHouse otherwise substitutes min(timestamp) into the time predicate.
	query := fmt.Sprintf(`SELECT formatDateTime(min(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS timestamp,event_id,source,collector_instance_id,subject_ip,min(payload_json) AS payload_json,uniqExact(payload_json) AS payload_versions FROM shared_observation_events_v2
 PREWHERE sensor_id=%s AND campus_id=%s AND access_domain=%s AND subject_ip IN ('',%s)
 AND timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<=parseDateTime64BestEffort(%s,6)
 GROUP BY event_id,source,collector_instance_id,subject_ip ORDER BY event_id LIMIT 2001
 SETTINGS prefer_column_name_to_alias=1,max_threads=1,max_memory_usage=134217728,max_execution_time=2 FORMAT JSONEachRow`, chQuote(scope.SensorID), chQuote(scope.CampusID), chQuote(scope.AccessDomain), chQuote(scope.IP), chQuote(now.Add(-11*time.Minute).Format(time.RFC3339Nano)), chQuote(now.Format(time.RFC3339Nano)))
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return sharedaccess.Window{}, sharedaccess.BehaviorAssessment{}, err
	}
	rows := []sharedObservationEvent{}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return sharedaccess.Window{}, sharedaccess.BehaviorAssessment{}, err
	}
	if len(rows) > 2000 {
		return sharedaccess.Window{}, sharedaccess.BehaviorAssessment{}, fmt.Errorf("shared observation query exceeded bound")
	}
	w, item, err := buildHandshakeObservation(scope, cfg, rows, now)
	if err != nil {
		return w, item, err
	}
	return s.includeSharedGateway(ctx, scope, cfg, w, item, now)
}

func buildHandshakeObservation(scope SharedObservationScope, cfg sharedaccess.Config, rows []sharedObservationEvent, now time.Time) (sharedaccess.Window, sharedaccess.BehaviorAssessment, error) {
	w := sharedaccess.Window{SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, IP: scope.IP, RuleVersion: sharedaccess.RuleVersion, Samples: map[string]map[string]sharedaccess.FeatureSample{}, Records: []sharedaccess.RecordRef{}, EventIDs: []string{}, Conflicts: []string{}}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.EventID != b.EventID {
			return a.EventID < b.EventID
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		return a.Payload < b.Payload
	})
	facts := []sharedaccess.CoverageFact{}
	seenRows := map[string]string{}
	seen := map[string]string{}
	globalConflicts := map[string]bool{}
	sources := map[string]bool{}
	legacy := false
	for _, row := range rows {
		rowKey := row.Source + "/" + row.Instance + "/" + row.EventID
		value := row.IP + "/" + row.Payload
		if old, ok := seenRows[rowKey]; ok {
			if old != value {
				if row.IP == scope.IP {
					w.Conflicts = append(w.Conflicts, "duplicate_event_changed")
				} else {
					globalConflicts[row.Source+"/"+row.Instance] = true
				}
			}
			continue
		}
		seenRows[rowKey] = value
		var payload struct {
			Schema   string                         `json:"handshake_schema"`
			Samples  []sharedaccess.HandshakeSample `json:"feature_samples"`
			Coverage sharedaccess.CoverageV2        `json:"capture_coverage"`
			UA       []string                       `json:"user_agents"`
		}
		if err := json.Unmarshal([]byte(row.Payload), &payload); err != nil {
			return w, sharedaccess.BehaviorAssessment{}, err
		}
		facts = append(facts, sharedaccess.CoverageFact{EventID: row.EventID, Source: row.Source, Instance: row.Instance, IP: row.IP, Coverage: payload.Coverage})
		if row.PayloadVersions > 1 {
			if row.IP == scope.IP {
				w.Conflicts = append(w.Conflicts, "duplicate_event_changed")
			} else {
				globalConflicts[row.Source+"/"+row.Instance] = true
			}
			continue
		}
		if row.IP != scope.IP {
			continue
		}
		contributed := false
		if payload.Schema != "handshake-samples/v1" {
			legacy = true
			at, e := time.Parse(time.RFC3339Nano, row.Timestamp)
			if e == nil && !at.Before(now.Add(-10*time.Minute)) && !at.After(now) {
				if w.From.IsZero() || at.Before(w.From) {
					w.From = at
				}
				if at.After(w.To) {
					w.To = at
				}
				contributed = true
			}
			for _, ua := range payload.UA {
				for family, value := range sharedaccess.HandshakeFeatures("user_agent", ua) {
					if w.Samples[family] == nil {
						w.Samples[family] = map[string]sharedaccess.FeatureSample{}
					}
					if _, ok := w.Samples[family][value]; !ok {
						w.Samples[family][value] = sharedaccess.FeatureSample{Buckets: []int64{}}
					}
				}
			}
		}
		for _, sample := range payload.Samples {
			if (sample.Bucket != 0 && sample.Bucket != sample.ObservedAt.Unix()/5) || sample.EventID == "" || sample.ObservedAt.Before(now.Add(-10*time.Minute)) || sample.ObservedAt.After(now) || sample.ObservedAt.Before(payload.Coverage.From) || !sample.ObservedAt.Before(payload.Coverage.To) {
				continue
			}
			for family, value := range sharedaccess.HandshakeFeatures(sample.Family, sample.Value) {
				key := row.Source + "/" + family + "/" + sample.EventID
				if old, ok := seen[key]; ok {
					if old != value {
						w.Conflicts = append(w.Conflicts, "duplicate_feature_changed")
					}
					continue
				}
				seen[key] = value
				if w.Samples[family] == nil {
					w.Samples[family] = map[string]sharedaccess.FeatureSample{}
				}
				if len(w.Samples[family]) >= 64 {
					w.Conflicts = append(w.Conflicts, "feature_value_limit")
					continue
				}
				feature := w.Samples[family][value]
				feature.Count++
				bucket := sample.ObservedAt.Unix() / 5
				found := false
				for _, v := range feature.Buckets {
					if v == bucket {
						found = true
					}
				}
				if !found {
					feature.Buckets = append(feature.Buckets, bucket)
					sort.Slice(feature.Buckets, func(i, j int) bool { return feature.Buckets[i] < feature.Buckets[j] })
				}
				w.Samples[family][value] = feature
				contributed = true
				if w.From.IsZero() || sample.ObservedAt.Before(w.From) {
					w.From = sample.ObservedAt
				}
				if sample.ObservedAt.After(w.To) {
					w.To = sample.ObservedAt
				}
			}
		}
		if contributed {
			w.EventIDs = append(w.EventIDs, row.EventID)
			w.Records = append(w.Records, sharedaccess.RecordRef{EventID: row.EventID, Source: row.Source, InstanceID: row.Instance})
			sources[row.Source] = true
		}
	}
	for source := range sources {
		w.Sources = append(w.Sources, source)
	}
	for _, ref := range w.Records {
		if globalConflicts[ref.Source+"/"+ref.InstanceID] {
			w.Conflicts = append(w.Conflicts, "duplicate_event_changed")
		}
	}
	sort.Strings(w.Sources)
	sort.Strings(w.EventIDs)
	w.LastObservedAt = w.To
	w.UAOS = featureValues(w.Samples["ua_os"])
	w.TLSStacks = featureValues(w.Samples["tls_stack"])
	w.Conflicts = append(w.Conflicts, sharedaccess.VerifyCoverage(w, cfg, facts)...)
	if legacy {
		w.Conflicts = append(w.Conflicts, "legacy_summary_without_timing")
	}
	for _, fact := range facts {
		if fact.Coverage.From.Before(w.To) && fact.Coverage.To.After(w.From) {
			w.CoverageFacts = append(w.CoverageFacts, fact)
		}
	}
	sort.Slice(w.CoverageFacts, func(i, j int) bool { return w.CoverageFacts[i].EventID < w.CoverageFacts[j].EventID })
	sort.Strings(w.Conflicts)
	w.Complete = len(w.Conflicts) == 0
	w.CoverageVerified = w.Complete
	return finalizeSharedObservation(w, cfg, now)
}

func finalizeSharedObservation(w sharedaccess.Window, cfg sharedaccess.Config, now time.Time) (sharedaccess.Window, sharedaccess.BehaviorAssessment, error) {
	evidenceRaw, _ := json.Marshal(struct {
		Samples   any
		Records   any
		Coverage  any
		Conflicts any
		Clients   any
		Gateway   any
		From, To  time.Time
		Config    string
	}{w.Samples, w.Records, w.CoverageFacts, w.Conflicts, w.AssociatedClients, w.GatewayLease, w.From, w.To, cfg.ID()})
	w.ID = policy.StableID(sharedaccess.BehaviorRuleVersion, w.SensorID, w.CampusID, w.AccessDomain, w.IP, string(evidenceRaw))
	endpointID := ""
	if w.GatewayMAC != "" {
		endpointID = "mac:" + w.GatewayMAC
	}
	item, present := sharedaccess.AssessBehavior(w.ID, endpointID, w, sharedaccess.BehaviorRouterContext{}, cfg.DeviceBound())
	if !present {
		item = sharedaccess.BehaviorAssessment{ObservationID: w.ID, SensorID: w.SensorID, CampusID: w.CampusID, AccessDomain: w.AccessDomain, IP: w.IP, Status: "candidate", RuleVersion: sharedaccess.BehaviorRuleVersion, WindowStart: w.From, WindowEnd: w.To, FirstSeen: w.From, LastSeen: w.To, ExpiresAt: now.Add(30 * 24 * time.Hour), FeatureSamples: w.Samples, SignalGroups: []string{}, Reasons: []string{"当前证据未满足确认共享标准"}, Conflicts: w.Conflicts, EventIDs: w.EventIDs, KnownDevices: []sharedaccess.KnownDevice{}, ScoreComponents: []sharedaccess.BehaviorScoreComponent{}, CoverageState: "partial"}
	}
	if w.Complete && w.CoverageVerified && len(w.Conflicts) == 0 {
		item.CoverageState = "verified"
	}
	if w.From.IsZero() {
		w.From = now.Add(-10 * time.Minute)
		w.To = now
		item.FirstSeen = w.From
		item.LastSeen = w.To
		item.WindowStart = w.From
		item.WindowEnd = w.To
	}
	item.Current = !w.LastObservedAt.IsZero() && now.Sub(w.LastObservedAt) <= cfg.Freshness()
	w.StrongAnchor, w.DeviceLowerBound = item.StrongAnchor, item.DeviceLowerBound
	return w, item, nil
}

// PersistSharedObservationTx shares the caller's transaction with the decision
// and job acknowledgement. It does not write risk or action projections.
func PersistSharedObservationTx(ctx context.Context, tx *sql.Tx, item sharedaccess.BehaviorAssessment) error {
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE shared_behavior_observations SET current=false WHERE sensor_id=$1 AND campus_id=$2 AND access_domain=$3 AND ip=$4::inet AND current AND observation_id<>$5`, item.SensorID, item.CampusID, item.AccessDomain, item.IP, item.ObservationID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_behavior_observations(observation_id,sensor_id,campus_id,access_domain,ip,status,confidence,signal_groups,rule_version,coverage_state,first_seen,last_seen,window_start,window_end,expires_at,observation,current)
 VALUES($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
 ON CONFLICT(observation_id) DO UPDATE SET observation=EXCLUDED.observation,current=EXCLUDED.current,status=EXCLUDED.status,confidence=EXCLUDED.confidence,coverage_state=EXCLUDED.coverage_state,updated_at=now()`, item.ObservationID, item.SensorID, item.CampusID, item.AccessDomain, item.IP, item.Status, item.Confidence, item.SignalGroups, item.RuleVersion, item.CoverageState, item.FirstSeen, item.LastSeen, item.WindowStart, item.WindowEnd, item.ExpiresAt, raw, item.Current)
	return err
}

type SharedObservationProfileKey struct {
	SensorID   string    `json:"sensor_id"`
	CampusID   string    `json:"campus_id"`
	EndpointID string    `json:"endpoint_id"`
	IP         string    `json:"ip"`
	ObservedAt time.Time `json:"observed_at"`
}

func EnqueueSharedDeviceProfileJobsForObservations(ctx context.Context, tx *sql.Tx, items []SharedObservationProfileKey) error {
	if len(items) == 0 {
		return nil
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO shared_device_profile_jobs(subject_key,sensor_id,campus_id,endpoint_id,mac,ip,vlan,observed_at)
SELECT
  coalesce(nullif(r.sensor_id,''),'') || ':' ||
  CASE WHEN coalesce(r.endpoint_id,'')<>'' THEN 'endpoint:'||r.endpoint_id
       ELSE 'address:'||coalesce(r.campus_id,'')||':'||':'||host(r.ip)
  END,
  coalesce(r.sensor_id,''), coalesce(r.campus_id,''), coalesce(r.endpoint_id,''),
  '', r.ip, '', r.observed_at
FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,campus_id text,endpoint_id text,ip inet,observed_at timestamptz)
WHERE r.observed_at >= (SELECT cutover_at FROM shared_device_profile_runtime WHERE singleton)
ON CONFLICT(subject_key) DO UPDATE SET
  dirty_generation = shared_device_profile_jobs.dirty_generation+1,
  dirty_since = CASE WHEN shared_device_profile_jobs.processed_generation>=shared_device_profile_jobs.dirty_generation
    THEN now() ELSE shared_device_profile_jobs.dirty_since END,
  observed_at = greatest(shared_device_profile_jobs.observed_at, EXCLUDED.observed_at),
  not_before = least(shared_device_profile_jobs.not_before, now()),
  updated_at = now()`, raw)
	return err
}

func enqueueSharedDeviceProfileJobsForObservationsDB(ctx context.Context, db *sql.DB, items []SharedObservationProfileKey) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = EnqueueSharedDeviceProfileJobsForObservations(ctx, tx, items); err != nil {
		return err
	}
	return tx.Commit()
}
