package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/sharedaccess"
)

type sharedBehaviorSignalRow struct {
	SensorID      string     `json:"sensor_id"`
	CampusID      string     `json:"campus_id"`
	AccessDomain  string     `json:"access_domain"`
	IP            string     `json:"ip"`
	FeatureFamily string     `json:"feature_family"`
	FeatureValue  string     `json:"feature_value"`
	FeatureCount  int        `json:"feature_count"`
	Buckets       []int64    `json:"buckets"`
	EventIDs      []string   `json:"event_ids"`
	Sources       []string   `json:"sources"`
	EventRefs     [][]string `json:"event_refs"`
	FirstSeen     string     `json:"first_seen"`
	LastSeen      string     `json:"last_seen"`
}

type sharedBehaviorGroup struct {
	window     sharedaccess.Window
	seen       map[string]bool
	recordSeen map[string]bool
	sources    map[string]bool
}

type sharedBehaviorCheckpoint struct {
	eventAt   sql.NullTime
	updatedAt time.Time
}

func stableSharedBehaviorID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "shared-behavior-" + hex.EncodeToString(sum[:16])
}

func (s *DBStore) sharedBehaviorSignalRows(ctx context.Context, sensorID string, from, to time.Time) ([]sharedBehaviorSignalRow, error) {
	query := fmt.Sprintf(`SELECT sensor_id,campus_id,access_domain,subject_ip AS ip,feature_family,feature_value,
 uniqExact(event_id) AS feature_count,
 arraySlice(arraySort(groupUniqArray(toInt64(toUnixTimestamp64Milli(timestamp)/5000))),1,128) AS buckets,
 arraySlice(groupUniqArray(event_id),1,8) AS event_ids,
 arraySort(groupUniqArray(source)) AS sources,
 arraySlice(groupUniqArray(tuple(event_id,source,collector_instance_id)),1,8) AS event_refs,
 formatDateTime(min(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS first_seen,
 formatDateTime(max(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS last_seen
FROM shared_behavior_signal_events_v1
PREWHERE sensor_id=%s AND timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<parseDateTime64BestEffort(%s,6)
WHERE subject_ip!='' AND feature_value!=''
GROUP BY sensor_id,campus_id,access_domain,ip,feature_family,feature_value
ORDER BY ip,feature_family,feature_value
LIMIT 100000 SETTINGS max_threads=2,max_memory_usage=536870912,max_execution_time=20 FORMAT JSONEachRow`,
		chQuote(sensorID), chQuote(from.UTC().Format(time.RFC3339Nano)), chQuote(to.UTC().Format(time.RFC3339Nano)))
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return nil, err
	}
	rows := []sharedBehaviorSignalRow{}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return nil, err
	}
	if len(rows) >= 100000 {
		return nil, fmt.Errorf("shared behavior signal result reached safety limit")
	}
	return rows, nil
}

func (s *DBStore) sharedBehaviorCoverage(ctx context.Context, sensorID string, windowEnd time.Time) (bool, []string, error) {
	rows, err := s.pg.db.QueryContext(ctx, `SELECT source_kind,max(last_event_at),max(updated_at)
FROM ingest_checkpoints WHERE sensor_id=$1 AND source_kind IN ('zeek-http','suricata','device-signals') GROUP BY source_kind`, sensorID)
	if err != nil {
		return false, nil, err
	}
	defer rows.Close()
	checkpoints := map[string]sharedBehaviorCheckpoint{}
	for rows.Next() {
		var kind string
		var eventAt sql.NullTime
		var updatedAt time.Time
		if err = rows.Scan(&kind, &eventAt, &updatedAt); err != nil {
			return false, nil, err
		}
		checkpoints[kind] = sharedBehaviorCheckpoint{eventAt: eventAt, updatedAt: updatedAt}
	}
	if err = rows.Err(); err != nil {
		return false, nil, err
	}
	reasons := sharedBehaviorCoverageReasons(checkpoints, windowEnd, time.Now().UTC())
	return len(reasons) == 0, reasons, nil
}

func sharedBehaviorCoverageReasons(checkpoints map[string]sharedBehaviorCheckpoint, windowEnd, now time.Time) []string {
	health := func(kind string) (bool, []string) {
		checkpoint, found := checkpoints[kind]
		if !found {
			return false, []string{kind + "_checkpoint_missing"}
		}
		reasons := []string{}
		if !checkpoint.eventAt.Valid || checkpoint.eventAt.Time.Before(windowEnd.Add(-90*time.Second)) {
			reasons = append(reasons, kind+"_event_lag")
		}
		if now.Sub(checkpoint.updatedAt) > 2*time.Minute {
			reasons = append(reasons, kind+"_checkpoint_stale")
		}
		return len(reasons) == 0, reasons
	}
	reasons := []string{}
	if healthy, deviceReasons := health("device-signals"); !healthy {
		reasons = append(reasons, deviceReasons...)
	}
	// HTTP/TLS identity signals may come from either Suricata EVE or Zeek HTTP.
	// Requiring a collector that is not configured makes otherwise complete
	// deployments permanently partial.
	suricataHealthy, suricataReasons := health("suricata")
	zeekHealthy, zeekReasons := health("zeek-http")
	if !suricataHealthy && !zeekHealthy {
		if _, found := checkpoints["suricata"]; found {
			reasons = append(reasons, suricataReasons...)
		}
		if _, found := checkpoints["zeek-http"]; found {
			reasons = append(reasons, zeekReasons...)
		}
		if _, suricataFound := checkpoints["suricata"]; !suricataFound {
			if _, zeekFound := checkpoints["zeek-http"]; !zeekFound {
				reasons = append(reasons, "application_checkpoint_missing")
			}
		}
	}
	sort.Strings(reasons)
	return reasons
}

func buildSharedBehaviorWindows(rows []sharedBehaviorSignalRow, from, to time.Time, complete bool, coverageReasons []string) ([]sharedaccess.Window, error) {
	groups := map[string]*sharedBehaviorGroup{}
	for _, row := range rows {
		ip := net.ParseIP(row.IP)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || row.FeatureFamily == "" || row.FeatureValue == "" {
			continue
		}
		_, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.FirstSeen))
		if err != nil {
			return nil, err
		}
		lastSeen, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.LastSeen))
		if err != nil {
			return nil, err
		}
		key := strings.Join([]string{row.SensorID, row.CampusID, row.AccessDomain, row.IP}, "\x00")
		group := groups[key]
		if group == nil {
			group = &sharedBehaviorGroup{window: sharedaccess.Window{
				RuleVersion: sharedaccess.RuleVersion, IP: row.IP, SensorID: row.SensorID,
				CampusID: row.CampusID, AccessDomain: row.AccessDomain, From: from, To: to,
				LastObservedAt: lastSeen, Complete: complete, CoverageVerified: complete,
				Samples: map[string]map[string]sharedaccess.FeatureSample{}, Conflicts: append([]string{}, coverageReasons...),
			}, seen: map[string]bool{}, recordSeen: map[string]bool{}, sources: map[string]bool{}}
			groups[key] = group
		}
		if lastSeen.After(group.window.LastObservedAt) {
			group.window.LastObservedAt = lastSeen
		}
		if group.window.Samples[row.FeatureFamily] == nil {
			group.window.Samples[row.FeatureFamily] = map[string]sharedaccess.FeatureSample{}
		}
		count := row.FeatureCount
		if count > 3 {
			count = 3
		}
		group.window.Samples[row.FeatureFamily][row.FeatureValue] = sharedaccess.FeatureSample{Count: count, Buckets: append([]int64{}, row.Buckets...)}
		for _, eventID := range row.EventIDs {
			if eventID != "" && !group.seen[eventID] && len(group.window.EventIDs) < 64 {
				group.seen[eventID] = true
				group.window.EventIDs = append(group.window.EventIDs, eventID)
			}
		}
		for _, source := range row.Sources {
			if source != "" {
				group.sources[source] = true
			}
		}
		for _, ref := range row.EventRefs {
			if len(ref) < 2 || ref[0] == "" || ref[1] == "" {
				continue
			}
			instanceID := ""
			if len(ref) > 2 {
				instanceID = ref[2]
			}
			key := strings.Join([]string{ref[0], ref[1], instanceID}, "\x00")
			if group.recordSeen[key] || len(group.window.Records) >= 64 {
				continue
			}
			group.recordSeen[key] = true
			group.sources[ref[1]] = true
			group.window.Records = append(group.window.Records, sharedaccess.RecordRef{EventID: ref[0], Source: ref[1], InstanceID: instanceID})
		}
	}
	out := make([]sharedaccess.Window, 0, len(groups))
	for _, group := range groups {
		window := group.window
		window.UAOS = featureValues(window.Samples["ua_os"])
		window.TTLPaths = featureValues(window.Samples["ttl_path"])
		window.TCPStacks = featureValues(window.Samples["tcp_stack"])
		window.TLSStacks = featureValues(window.Samples["tls_stack"])
		window.DHCPProfiles = featureValues(window.Samples["dhcp_stack"])
		for source := range group.sources {
			window.Sources = append(window.Sources, source)
		}
		sort.Strings(window.Sources)
		sort.Slice(window.Records, func(i, j int) bool {
			if window.Records[i].EventID != window.Records[j].EventID {
				return window.Records[i].EventID < window.Records[j].EventID
			}
			if window.Records[i].Source != window.Records[j].Source {
				return window.Records[i].Source < window.Records[j].Source
			}
			return window.Records[i].InstanceID < window.Records[j].InstanceID
		})
		window.ID = stableSharedBehaviorID(window.SensorID, window.CampusID, window.AccessDomain, window.IP, from.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano))
		sort.Strings(window.EventIDs)
		out = append(out, window)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func confirmedSharedBehaviorEvidence(window sharedaccess.Window, item sharedaccess.BehaviorAssessment) (evidence.Evidence, bool) {
	if item.Status != "confirmed" || item.CoverageState != "verified" || !window.Complete || !window.CoverageVerified || len(window.Conflicts) > 0 || len(window.Sources) == 0 || len(window.Records) == 0 {
		return evidence.Evidence{}, false
	}
	return evidence.Evidence{
		EvidenceID: window.ID, IP: window.IP, Type: "shared_access_window", Window: window.To.Sub(window.From).String(),
		Score: item.Confidence, Confidence: float64(item.Confidence) / 100, Severity: "info",
		Reason:  "高置信共享网关观察；仍须通过来源注册、权威账号归属、会话连续性和人工复核",
		Samples: []string{}, CreatedAt: window.LastObservedAt.UTC().Format(time.RFC3339Nano), SharedAccess: &window,
	}, true
}

func featureValues(values map[string]sharedaccess.FeatureSample) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (s *DBStore) sharedBehaviorRouter(ctx context.Context, endpointID, ip string, at time.Time) (sharedaccess.BehaviorRouterContext, error) {
	var raw []byte
	err := s.pg.db.QueryRowContext(ctx, `SELECT assessment FROM router_assessments
WHERE expires_at>$3 AND (($1<>'' AND endpoint_id=$1) OR ip=NULLIF($2,'')::inet)
ORDER BY CASE WHEN $1<>'' AND endpoint_id=$1 THEN 0 ELSE 1 END,
 CASE status WHEN 'confirmed' THEN 0 WHEN 'likely' THEN 1 ELSE 2 END,confidence DESC,last_seen DESC LIMIT 1`, endpointID, ip, at).Scan(&raw)
	if err == sql.ErrNoRows {
		return sharedaccess.BehaviorRouterContext{}, nil
	}
	if err != nil {
		return sharedaccess.BehaviorRouterContext{}, err
	}
	var item evidence.RouterAssessment
	if err = json.Unmarshal(raw, &item); err != nil {
		return sharedaccess.BehaviorRouterContext{}, err
	}
	return sharedaccess.BehaviorRouterContext{AssessmentID: item.AssessmentID, Brand: item.Brand, Model: item.Model, Role: item.Role, Status: item.Status, Confidence: item.Confidence}, nil
}

func (s *DBStore) persistSharedBehavior(ctx context.Context, item sharedaccess.BehaviorAssessment) error {
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_behavior_observations(
 observation_id,sensor_id,campus_id,access_domain,ip,endpoint_id,router_assessment_id,status,confidence,
 signal_groups,rule_version,coverage_state,first_seen,last_seen,window_start,window_end,expires_at,observation)
VALUES($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
ON CONFLICT(observation_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,router_assessment_id=EXCLUDED.router_assessment_id,
 status=EXCLUDED.status,confidence=EXCLUDED.confidence,signal_groups=EXCLUDED.signal_groups,
 rule_version=EXCLUDED.rule_version,coverage_state=EXCLUDED.coverage_state,
 last_seen=GREATEST(shared_behavior_observations.last_seen,EXCLUDED.last_seen),
 expires_at=EXCLUDED.expires_at,observation=EXCLUDED.observation,updated_at=now()`,
		item.ObservationID, item.SensorID, item.CampusID, item.AccessDomain, item.IP, item.EndpointID, item.Router.AssessmentID,
		item.Status, item.Confidence, item.SignalGroups, item.RuleVersion, item.CoverageState, item.FirstSeen, item.LastSeen,
		item.WindowStart, item.WindowEnd, item.ExpiresAt, raw)
	if err != nil {
		return err
	}
	// Repair history written by older workers that interpreted the UTC signal
	// stream's zone-less ClickHouse text as Asia/Shanghai. A history timestamp
	// for this immutable observation window must remain inside that window.
	_, err = tx.ExecContext(ctx, `UPDATE shared_behavior_observation_history SET observed_at=$2
WHERE observation_id=$1 AND (observed_at<$3 OR observed_at>$4)`, item.ObservationID, item.LastSeen, item.WindowStart, item.WindowEnd)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_behavior_observation_history(
 observation_id,status,confidence,signal_groups,coverage_state,rule_version,observation,observed_at)
SELECT $1,$2,$3,$4,$5,$6,$7,$8 WHERE NOT EXISTS(
 SELECT 1 FROM shared_behavior_observation_history WHERE observation_id=$1 AND status=$2 AND confidence=$3
 AND signal_groups=$4 AND coverage_state=$5 AND rule_version=$6)`, item.ObservationID, item.Status, item.Confidence, item.SignalGroups, item.CoverageState, item.RuleVersion, raw, item.LastSeen)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *DBStore) materializeSharedBehavior(ctx context.Context, sensorID string, now time.Time) (int, error) {
	windowEnd := now.UTC().Add(-90 * time.Second).Truncate(5 * time.Minute)
	windowStart := windowEnd.Add(-10 * time.Minute)
	rows, err := s.sharedBehaviorSignalRows(ctx, sensorID, windowStart, windowEnd)
	if err != nil {
		return 0, err
	}
	complete, coverageReasons, err := s.sharedBehaviorCoverage(ctx, sensorID, windowEnd)
	if err != nil {
		return 0, err
	}
	windows, err := buildSharedBehaviorWindows(rows, windowStart, windowEnd, complete, coverageReasons)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, window := range windows {
		attribution, found, resolveErr := s.ResolveDeviceAt(ctx, DomainObservation{IP: window.IP, Timestamp: window.LastObservedAt.Format(time.RFC3339Nano), SensorID: window.SensorID, CampusID: window.CampusID})
		if resolveErr != nil {
			return written, resolveErr
		}
		endpointID := ""
		if found && !attribution.Conflict {
			endpointID = attribution.EndpointID
		} else if found && attribution.Conflict {
			window.Complete = false
			window.CoverageVerified = false
			window.Conflicts = append(window.Conflicts, "ambiguous_endpoint_association")
		}
		router, routerErr := s.sharedBehaviorRouter(ctx, endpointID, window.IP, window.LastObservedAt)
		if routerErr != nil {
			return written, routerErr
		}
		item, present := sharedaccess.AssessBehavior(window.ID, endpointID, window, router)
		if !present {
			continue
		}
		if err = s.persistSharedBehavior(ctx, item); err != nil {
			return written, err
		}
		if err = s.writeSharedGatewayRouterEvidence(ctx, item); err != nil {
			return written, err
		}
		if bridge, ok := confirmedSharedBehaviorEvidence(window, item); ok {
			if err = s.WriteEvidence(ctx, []evidence.Evidence{bridge}); err != nil {
				return written, err
			}
		}
		written++
	}
	_, _ = s.pg.db.ExecContext(ctx, `DELETE FROM shared_behavior_observations WHERE expires_at<now()`)
	state, _ := json.Marshal(map[string]any{"as_of": windowEnd, "window_start": windowStart, "rows": len(rows), "observations": written, "coverage_verified": complete, "coverage_blockers": coverageReasons})
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('shared-behavior',$1,now())
ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, state)
	return written, err
}

func (s *DBStore) writeSharedGatewayRouterEvidence(ctx context.Context, item sharedaccess.BehaviorAssessment) error {
	if item.CoverageState != "verified" || (item.Status != "likely" && item.Status != "confirmed") || len(item.Conflicts) > 0 {
		return nil
	}
	behaviorGroups := []string{}
	for _, group := range item.SignalGroups {
		if group != "router_identity" {
			behaviorGroups = append(behaviorGroups, group)
		}
	}
	if len(behaviorGroups) < 2 {
		return nil
	}
	var raw []byte
	err := s.pg.db.QueryRowContext(ctx, `SELECT assessment FROM router_assessments
WHERE ip=$1::inet
ORDER BY (endpoint_id=$2 AND $2<>'') DESC,(mac<>'') DESC,(expires_at>$3) DESC,
 infrastructure ASC,ambiguous ASC,confidence DESC,last_seen DESC LIMIT 1`, item.IP, item.EndpointID, item.LastSeen).Scan(&raw)
	router := evidence.RouterAssessment{}
	if err == sql.ErrNoRows {
		err = nil
	}
	if err != nil {
		return err
	}
	if len(raw) > 0 {
		err = json.Unmarshal(raw, &router)
	}
	if err != nil {
		return err
	}
	if router.AssessmentID == "" {
		router.AssessmentID = stableSharedBehaviorID("router-assessment", item.EndpointID, item.IP)
		router.EndpointID, router.IP, router.AssociationQuality = item.EndpointID, item.IP, "shared_gateway_window"
		if strings.HasPrefix(item.EndpointID, "mac:") {
			router.MAC = strings.TrimPrefix(item.EndpointID, "mac:")
		}
	}
	sort.Strings(behaviorGroups)
	score := item.Confidence
	if score < 60 {
		score = 60
	}
	if score > 85 {
		score = 85
	}
	ruleVersion := fingerprint.DefaultRouterRuleSet().Version
	expiresAt := item.LastSeen.Add(24 * time.Hour)
	evidenceID := stableSharedBehaviorID("router-role", router.AssessmentID, strings.Join(behaviorGroups, ","))
	brand, series, model := router.Brand, router.Series, router.Model
	if router.BrandReferenceOnly {
		brand, series, model = "", "", ""
	}
	bridge := evidence.RouterEvidence{
		EvidenceID: evidenceID, AssessmentID: router.AssessmentID, Kind: "router_signal",
		EndpointID: router.EndpointID, IP: router.IP, MAC: router.MAC, Brand: brand,
		Series: series, Model: model, Role: "router", Source: "shared-behavior-materializer",
		SourceFamily: "shared_gateway_behavior", SourceEventType: "shared_access_window",
		RawValue: strings.Join(behaviorGroups, ","), Strength: "strong", Score: score,
		RuleID: "verified-shared-gateway-role", RuleVersion: ruleVersion,
		Explanation:        "重复共现的多终端协议栈与 TTL 路径表明该设备承担共享网关角色",
		AssociationQuality: router.AssociationQuality, Ambiguous: router.Ambiguous,
		FirstSeen: item.FirstSeen.UTC().Format(time.RFC3339Nano), LastSeen: item.LastSeen.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), EventIDs: append([]string{}, item.EventIDs...),
	}
	if len(bridge.EventIDs) > 20 {
		bridge.EventIDs = bridge.EventIDs[:20]
	}
	return s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: ruleVersion, ShadowMode: true, Evidence: []evidence.RouterEvidence{bridge}})
}
