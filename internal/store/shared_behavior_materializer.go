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
	"proxy-sentinel/internal/risk"
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

type sharedBehaviorKnownDeviceRow struct {
	SensorID     string  `json:"sensor_id"`
	CampusID     string  `json:"campus_id"`
	AccessDomain string  `json:"access_domain"`
	IP           string  `json:"ip"`
	Value        string  `json:"value"`
	Count        int     `json:"count"`
	Buckets      []int64 `json:"buckets"`
	FirstSeen    string  `json:"first_seen"`
	LastSeen     string  `json:"last_seen"`
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

func (s *DBStore) sharedBehaviorKnownDeviceRows(ctx context.Context, sensorID string, subjectIPs []string, from, to time.Time) ([]sharedBehaviorKnownDeviceRow, error) {
	if len(subjectIPs) == 0 {
		return []sharedBehaviorKnownDeviceRow{}, nil
	}
	uniqueIPs := map[string]bool{}
	for _, ip := range subjectIPs {
		if strings.TrimSpace(ip) != "" {
			uniqueIPs[ip] = true
		}
	}
	ips := make([]string, 0, len(uniqueIPs))
	for ip := range uniqueIPs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	result := []sharedBehaviorKnownDeviceRow{}
	for start := 0; start < len(ips); start += 50 {
		end := start + 50
		if end > len(ips) {
			end = len(ips)
		}
		quoted := make([]string, 0, end-start)
		for _, ip := range ips[start:end] {
			quoted = append(quoted, chQuote(ip))
		}
		query := fmt.Sprintf(`SELECT sensor_id,campus_id,access_domain,subject_ip AS ip,feature_value AS value,
 uniqExact(event_id) AS count,
 arraySlice(arraySort(groupUniqArray(toInt64(toUnixTimestamp64Milli(timestamp)/300000))),1,288) AS buckets,
 formatDateTime(min(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS first_seen,
 formatDateTime(max(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS last_seen
FROM shared_behavior_device_model_events_v1
PREWHERE sensor_id=%s AND subject_ip IN (%s) AND timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<parseDateTime64BestEffort(%s,6)
WHERE feature_value!=''
GROUP BY sensor_id,campus_id,access_domain,ip,value
ORDER BY ip,count DESC,value
LIMIT 100 BY ip SETTINGS max_threads=2,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`,
			chQuote(sensorID), strings.Join(quoted, ","), chQuote(from.UTC().Format(time.RFC3339Nano)), chQuote(to.UTC().Format(time.RFC3339Nano)))
		raw, err := s.ch.query(ctx, query)
		if err != nil {
			return nil, err
		}
		rows := []sharedBehaviorKnownDeviceRow{}
		if err = decodeJSONEachRow(raw, &rows); err != nil {
			return nil, err
		}
		result = append(result, rows...)
	}
	return result, nil
}

func (s *DBStore) sharedBehaviorPhysicalIdentityRows(ctx context.Context, sensorID string, subjectIPs []string, from, to time.Time) ([]sharedBehaviorKnownDeviceRow, error) {
	if len(subjectIPs) == 0 {
		return []sharedBehaviorKnownDeviceRow{}, nil
	}
	uniqueIPs := map[string]bool{}
	for _, ip := range subjectIPs {
		if strings.TrimSpace(ip) != "" {
			uniqueIPs[ip] = true
		}
	}
	ips := make([]string, 0, len(uniqueIPs))
	for ip := range uniqueIPs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	result := []sharedBehaviorKnownDeviceRow{}
	for start := 0; start < len(ips); start += 50 {
		end := start + 50
		if end > len(ips) {
			end = len(ips)
		}
		quoted := make([]string, 0, end-start)
		for _, ip := range ips[start:end] {
			quoted = append(quoted, chQuote(ip))
		}
		query := fmt.Sprintf(`SELECT sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,subject_ip AS ip,
 if(endpoint_id!='',endpoint_id,if(subject_mac!='',concat('mac:',lower(subject_mac)),'')) AS value,
 uniqExact(event_id) AS count,
 arraySort(groupUniqArray(toInt64(toUnixTimestamp64Milli(timestamp)/300000))) AS buckets,
 formatDateTime(min(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS first_seen,
 formatDateTime(max(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS last_seen
FROM normalized_events
PREWHERE sensor_id=%s AND subject_ip IN (%s) AND timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<parseDateTime64BestEffort(%s,6)
WHERE value!='' AND value NOT LIKE 'infra:%%'
GROUP BY sensor_id,campus_id,access_domain,ip,value
ORDER BY ip,value
LIMIT 100 BY ip SETTINGS max_threads=2,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`,
			chQuote(sensorID), strings.Join(quoted, ","), chQuote(from.UTC().Format(time.RFC3339Nano)), chQuote(to.UTC().Format(time.RFC3339Nano)))
		raw, err := s.ch.query(ctx, query)
		if err != nil {
			return nil, err
		}
		rows := []sharedBehaviorKnownDeviceRow{}
		if err = decodeJSONEachRow(raw, &rows); err != nil {
			return nil, err
		}
		result = append(result, rows...)
	}
	return result, nil
}

type sharedBehaviorKnownDeviceAccumulator struct {
	device  sharedaccess.KnownDevice
	buckets map[int64]bool
}

func sharedBehaviorKnownDevices(rows []sharedBehaviorKnownDeviceRow) map[string][]sharedaccess.KnownDevice {
	groups := map[string]map[string]*sharedBehaviorKnownDeviceAccumulator{}
	for _, row := range rows {
		parts := strings.SplitN(row.Value, "|", 4)
		if len(parts) != 4 || strings.TrimSpace(parts[3]) == "" || row.Count <= 0 {
			continue
		}
		firstSeen, firstErr := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.FirstSeen))
		lastSeen, lastErr := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.LastSeen))
		if firstErr != nil || lastErr != nil {
			continue
		}
		key := strings.Join([]string{row.SensorID, row.CampusID, row.AccessDomain, row.IP}, "\x00")
		modelKey := strings.ToLower(strings.TrimSpace(parts[3]))
		if groups[key] == nil {
			groups[key] = map[string]*sharedBehaviorKnownDeviceAccumulator{}
		}
		item := groups[key][modelKey]
		if item == nil {
			item = &sharedBehaviorKnownDeviceAccumulator{device: sharedaccess.KnownDevice{
				IdentityID: stableSharedBehaviorID("known-device", key, modelKey), Brand: strings.TrimSpace(parts[0]),
				OSFamily: strings.TrimSpace(parts[1]), DeviceType: strings.TrimSpace(parts[2]), Model: strings.TrimSpace(parts[3]),
				FirstSeen: firstSeen, LastSeen: lastSeen,
			}, buckets: map[int64]bool{}}
			groups[key][modelKey] = item
		}
		if item.device.Brand == "" && strings.TrimSpace(parts[0]) != "" {
			item.device.Brand = strings.TrimSpace(parts[0])
		}
		if firstSeen.Before(item.device.FirstSeen) {
			item.device.FirstSeen = firstSeen
		}
		if lastSeen.After(item.device.LastSeen) {
			item.device.LastSeen = lastSeen
		}
		item.device.Observations += row.Count
		for _, bucket := range row.Buckets {
			item.buckets[bucket] = true
		}
	}
	result := map[string][]sharedaccess.KnownDevice{}
	for key, items := range groups {
		for _, item := range items {
			// Two observations in different five-minute buckets keep one-shot,
			// synthetic, or malformed user agents out of the device lower bound.
			if item.device.Observations < 2 || len(item.buckets) < 2 {
				continue
			}
			result[key] = append(result[key], item.device)
		}
		sort.Slice(result[key], func(i, j int) bool {
			if result[key][i].LastSeen != result[key][j].LastSeen {
				return result[key][i].LastSeen.After(result[key][j].LastSeen)
			}
			return result[key][i].Model < result[key][j].Model
		})
	}
	return result
}

// sharedBehaviorCoexistingDeviceIdentities only returns device identities when
// at least two eligible physical models overlap in two five-minute buckets in
// the current ten-minute window. A 24-hour model inventory is deliberately not
// accepted as a confirmation anchor.
func sharedBehaviorCoexistingDeviceIdentities(rows []sharedBehaviorKnownDeviceRow) map[string][]string {
	type identity struct {
		id      string
		buckets map[int64]bool
	}
	groups := map[string][]identity{}
	for _, row := range rows {
		identityValue := strings.TrimSpace(row.Value)
		if identityValue == "" || row.Count < 2 {
			continue
		}
		buckets := map[int64]bool{}
		for _, bucket := range row.Buckets {
			buckets[bucket] = true
		}
		if len(buckets) < 2 {
			continue
		}
		key := strings.Join([]string{row.SensorID, row.CampusID, row.AccessDomain, row.IP}, "\x00")
		groups[key] = append(groups[key], identity{id: identityValue, buckets: buckets})
	}
	result := map[string][]string{}
	for key, identities := range groups {
		accepted := map[string]bool{}
		for i := 0; i < len(identities); i++ {
			for j := i + 1; j < len(identities); j++ {
				overlap := 0
				for bucket := range identities[i].buckets {
					if identities[j].buckets[bucket] {
						overlap++
					}
				}
				if overlap >= 2 {
					accepted[identities[i].id], accepted[identities[j].id] = true, true
				}
			}
		}
		for id := range accepted {
			result[key] = append(result[key], id)
		}
		sort.Strings(result[key])
	}
	return result
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
		window.ID = stableSharedBehaviorID(window.SensorID, window.CampusID, window.AccessDomain, window.IP)
		sort.Strings(window.EventIDs)
		out = append(out, window)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func confirmedSharedBehaviorEvidence(window sharedaccess.Window, item sharedaccess.BehaviorAssessment) (evidence.Evidence, bool) {
	if item.Status != "confirmed" || item.StrongAnchor == "" || item.DeviceLowerBound < 2 || item.CoverageState != "verified" || !window.Complete || !window.CoverageVerified || len(window.Conflicts) > 0 || len(window.Sources) == 0 || len(window.Records) == 0 {
		return evidence.Evidence{}, false
	}
	return evidence.Evidence{
		EvidenceID: window.ID, IP: window.IP, Type: "shared_access_window", Window: window.To.Sub(window.From).String(),
		Score: item.Confidence, Confidence: float64(item.Confidence) / 100, Severity: "info",
		Reason:  "当前完整窗口的强锚点确认共享出口；保持影子模式并等待人工复核",
		Samples: []string{}, CreatedAt: window.LastObservedAt.UTC().Format(time.RFC3339Nano), SharedAccess: &window,
		RiskKind: "shared_access", StrongAnchor: item.StrongAnchor, DeviceLowerBound: item.DeviceLowerBound,
		CoverageState: item.CoverageState, GenerationID: item.GenerationID, EndpointID: item.EndpointID,
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

func mergeIEEE1905AssociationWindows(windows []sharedaccess.Window, groups []ieee1905AssociationGroup, from, to time.Time, complete bool, coverageReasons []string) []sharedaccess.Window {
	indexes := map[string]int{}
	for index := range windows {
		key := strings.Join([]string{windows[index].SensorID, windows[index].CampusID, windows[index].AccessDomain, windows[index].IP}, "\x00")
		indexes[key] = index
	}
	for _, group := range groups {
		if net.ParseIP(group.GatewayIP) == nil || len(group.Clients) == 0 {
			continue
		}
		key := strings.Join([]string{group.SensorID, group.CampusID, group.AccessDomain, group.GatewayIP}, "\x00")
		index, found := indexes[key]
		if !found {
			window := sharedaccess.Window{
				RuleVersion: sharedaccess.RuleVersion, IP: group.GatewayIP, SensorID: group.SensorID,
				CampusID: group.CampusID, AccessDomain: group.AccessDomain, From: from, To: to,
				LastObservedAt: to, Complete: complete, CoverageVerified: complete,
				Samples: map[string]map[string]sharedaccess.FeatureSample{}, Conflicts: append([]string{}, coverageReasons...),
				Sources: []string{"packet-sidecar"},
			}
			window.ID = stableSharedBehaviorID(window.SensorID, window.CampusID, window.AccessDomain, window.IP)
			windows = append(windows, window)
			index = len(windows) - 1
			indexes[key] = index
		}
		window := &windows[index]
		window.AssociatedClients = append([]string{}, group.Clients...)
		if window.Samples == nil {
			window.Samples = map[string]map[string]sharedaccess.FeatureSample{}
		}
		window.Samples["ieee1905_association"] = map[string]sharedaccess.FeatureSample{}
		bucket := to.UnixMilli() / 5000
		for _, client := range group.Clients {
			window.Samples["ieee1905_association"][client] = sharedaccess.FeatureSample{Count: 1, Buckets: []int64{bucket}}
		}
		sourcePresent := false
		for _, source := range window.Sources {
			if source == "packet-sidecar" {
				sourcePresent = true
			}
		}
		if !sourcePresent {
			window.Sources = append(window.Sources, "packet-sidecar")
			sort.Strings(window.Sources)
		}
		seenEvents := map[string]bool{}
		for _, eventID := range window.EventIDs {
			seenEvents[eventID] = true
		}
		for _, eventID := range group.EventIDs {
			if eventID == "" || seenEvents[eventID] || len(window.EventIDs) >= 64 {
				continue
			}
			seenEvents[eventID] = true
			window.EventIDs = append(window.EventIDs, eventID)
			window.Records = append(window.Records, sharedaccess.RecordRef{EventID: eventID, Source: "packet-sidecar"})
		}
		sort.Strings(window.EventIDs)
	}
	sort.Slice(windows, func(i, j int) bool { return windows[i].IP < windows[j].IP })
	return windows
}

func (s *DBStore) sharedBehaviorRouter(ctx context.Context, endpointID, ip string, at time.Time) (sharedaccess.BehaviorRouterContext, error) {
	var raw []byte
	var independentRole bool
	err := s.pg.db.QueryRowContext(ctx, `SELECT assessment,EXISTS(
 SELECT 1 FROM router_evidence_facts f
 WHERE f.assessment_id=router_assessments.assessment_id AND f.expires_at>$3
 AND f.source_family<>'shared_gateway_behavior' AND f.score>0 AND NOT f.conflict AND NOT f.exclusion
 AND COALESCE(f.data->>'role','') IN('router','ap')
 AND COALESCE(f.data->>'brand_reference_only','false')<>'true'
) FROM router_assessments
WHERE expires_at>$3 AND (($1<>'' AND endpoint_id=$1) OR ip=NULLIF($2,'')::inet)
ORDER BY CASE WHEN $1<>'' AND endpoint_id=$1 THEN 0 ELSE 1 END,
	CASE status WHEN 'confirmed' THEN 0 WHEN 'likely' THEN 1 ELSE 2 END,confidence DESC,last_seen DESC LIMIT 1`, endpointID, ip, at).Scan(&raw, &independentRole)
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
	if !independentRole {
		item.Role, item.Status, item.Confidence = "", "", 0
	}
	return sharedaccess.BehaviorRouterContext{AssessmentID: item.AssessmentID, Brand: item.Brand, Model: item.Model, Role: item.Role, Status: item.Status, Confidence: item.Confidence, BrandAttribution: item.BrandAttribution}, nil
}

func (s *DBStore) persistSharedBehaviorGeneration(ctx context.Context, generationID, sensorID string, windowStart, windowEnd time.Time, items []sharedaccess.BehaviorAssessment) error {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE shared_behavior_generations SET active=false WHERE sensor_id=$1 AND active`, sensorID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE shared_behavior_observations SET current=false,updated_at=now() WHERE sensor_id=$1 AND current`, sensorID); err != nil {
		return err
	}
	confirmed := 0
	for _, item := range items {
		if item.Status == "confirmed" {
			confirmed++
		}
		raw, marshalErr := json.Marshal(item)
		if marshalErr != nil {
			return marshalErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shared_behavior_observations(
 observation_id,sensor_id,campus_id,access_domain,ip,endpoint_id,router_assessment_id,status,confidence,
 signal_groups,rule_version,coverage_state,first_seen,last_seen,window_start,window_end,expires_at,observation,generation_id,current)
VALUES($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,true)
ON CONFLICT(observation_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,router_assessment_id=EXCLUDED.router_assessment_id,
 status=EXCLUDED.status,confidence=EXCLUDED.confidence,signal_groups=EXCLUDED.signal_groups,
 rule_version=EXCLUDED.rule_version,coverage_state=EXCLUDED.coverage_state,first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,
 window_start=EXCLUDED.window_start,window_end=EXCLUDED.window_end,expires_at=EXCLUDED.expires_at,
 observation=EXCLUDED.observation,generation_id=EXCLUDED.generation_id,current=true,updated_at=now()`,
			item.ObservationID, item.SensorID, item.CampusID, item.AccessDomain, item.IP, item.EndpointID, item.Router.AssessmentID,
			item.Status, item.Confidence, item.SignalGroups, item.RuleVersion, item.CoverageState, item.FirstSeen, item.LastSeen,
			item.WindowStart, item.WindowEnd, item.ExpiresAt, raw, generationID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shared_behavior_observation_history(
 observation_id,status,confidence,signal_groups,coverage_state,rule_version,observation,observed_at,generation_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(observation_id,generation_id) WHERE generation_id<>'' DO NOTHING`,
			item.ObservationID, item.Status, item.Confidence, item.SignalGroups, item.CoverageState, item.RuleVersion, raw, item.LastSeen, generationID)
		if err != nil {
			return err
		}
	}
	if err = replaceSharedRiskSnapshotsTx(ctx, tx); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_behavior_generations(
 generation_id,sensor_id,window_start,window_end,coverage_state,observation_count,confirmed_count,active)
VALUES($1,$2,$3,$4,'verified',$5,$6,true)
ON CONFLICT(generation_id) DO UPDATE SET coverage_state='verified',coverage_blockers='{}',observation_count=EXCLUDED.observation_count,
 confirmed_count=EXCLUDED.confirmed_count,active=true`, generationID, sensorID, windowStart, windowEnd, len(items), confirmed)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func replaceSharedRiskSnapshotsTx(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT observation FROM shared_behavior_observations
WHERE current AND status='confirmed' AND coverage_state='verified' ORDER BY confidence DESC,last_seen DESC`)
	if err != nil {
		return err
	}
	items := map[string]risk.Snapshot{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var assessment sharedaccess.BehaviorAssessment
		if err = json.Unmarshal(raw, &assessment); err != nil {
			rows.Close()
			return err
		}
		if snapshot, ok := risk.SnapshotForSharedBehavior(assessment); ok {
			if _, exists := items[snapshot.IP]; !exists {
				items[snapshot.IP] = snapshot
			}
		}
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO risk_snapshot_history(ip,snapshot) SELECT ip,to_jsonb(risk_snapshots) FROM risk_snapshots`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM risk_snapshots`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM subject_risk_snapshots`); err != nil {
		return err
	}
	for _, snapshot := range items {
		evidenceIDs, _ := json.Marshal(snapshot.EvidenceIDs)
		blockers, _ := json.Marshal(snapshot.AutomationBlockers)
		groups, _ := json.Marshal(snapshot.IndependentSignalGroups)
		metadata, _ := json.Marshal(snapshot)
		_, err = tx.ExecContext(ctx, `INSERT INTO risk_snapshots(
ip,score,level,confidence,"window",evidence_ids,summary,recommended_action,updated_at,assessment_level,
review_disposition,automation_eligible,automation_blockers,detection_basis,independent_signal_groups,metadata)
VALUES($1::inet,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, snapshot.IP, snapshot.Score,
			snapshot.Level, snapshot.Confidence, snapshot.Window, evidenceIDs, snapshot.Summary, snapshot.RecommendedAction,
			snapshot.UpdatedAt, snapshot.AssessmentLevel, snapshot.ReviewDisposition, snapshot.AutomationEligible, blockers,
			snapshot.DetectionBasis, groups, metadata)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO risk_snapshot_history(ip,snapshot) VALUES($1::inet,$2)`, snapshot.IP, metadata); err != nil {
			return err
		}
	}
	return nil
}

func (s *DBStore) recordIncompleteSharedBehaviorGeneration(ctx context.Context, generationID, sensorID string, windowStart, windowEnd time.Time, blockers []string) error {
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO shared_behavior_generations(
 generation_id,sensor_id,window_start,window_end,coverage_state,coverage_blockers,active)
VALUES($1,$2,$3,$4,'incomplete',$5,false)
ON CONFLICT(generation_id) DO UPDATE SET coverage_state='incomplete',coverage_blockers=EXCLUDED.coverage_blockers,active=false`, generationID, sensorID, windowStart, windowEnd, blockers)
	return err
}

func (s *DBStore) materializeSharedBehavior(ctx context.Context, sensorID string, now time.Time) (int, error) {
	windowEnd := now.UTC().Add(-90 * time.Second).Truncate(5 * time.Minute)
	windowStart := windowEnd.Add(-10 * time.Minute)
	generationID := stableSharedBehaviorID("generation", sensorID, windowStart.Format(time.RFC3339Nano), windowEnd.Format(time.RFC3339Nano))
	if err := s.syncIEEE1905Associations(ctx, sensorID, now); err != nil {
		return 0, err
	}
	associationGroups, err := s.activeIEEE1905AssociationGroups(ctx, sensorID)
	if err != nil {
		return 0, err
	}
	rows, err := s.sharedBehaviorSignalRows(ctx, sensorID, windowStart, windowEnd)
	if err != nil {
		return 0, err
	}
	complete, coverageReasons, err := s.sharedBehaviorCoverage(ctx, sensorID, windowEnd)
	if err != nil {
		return 0, err
	}
	if !complete {
		if err = s.recordIncompleteSharedBehaviorGeneration(ctx, generationID, sensorID, windowStart, windowEnd, coverageReasons); err != nil {
			return 0, err
		}
		state, _ := json.Marshal(map[string]any{"as_of": windowEnd, "generation_id": generationID, "window_start": windowStart, "coverage_state": "incomplete", "stale": true, "coverage_blockers": coverageReasons})
		_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('shared-behavior',$1,now())
ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, state)
		return 0, err
	}
	windows, err := buildSharedBehaviorWindows(rows, windowStart, windowEnd, complete, coverageReasons)
	if err != nil {
		return 0, err
	}
	windows = mergeIEEE1905AssociationWindows(windows, associationGroups, windowStart, windowEnd, complete, coverageReasons)
	windowIPs := make([]string, 0, len(windows))
	for _, window := range windows {
		windowIPs = append(windowIPs, window.IP)
	}
	referenceRows, err := s.sharedBehaviorKnownDeviceRows(ctx, sensorID, windowIPs, windowEnd.Add(-24*time.Hour), windowEnd)
	if err != nil {
		return 0, err
	}
	currentRows, err := s.sharedBehaviorPhysicalIdentityRows(ctx, sensorID, windowIPs, windowStart, windowEnd)
	if err != nil {
		return 0, err
	}
	referenceDevices := sharedBehaviorKnownDevices(referenceRows)
	currentIdentities := sharedBehaviorCoexistingDeviceIdentities(currentRows)
	items := make([]sharedaccess.BehaviorAssessment, 0, len(windows))
	windowsByID := make(map[string]sharedaccess.Window, len(windows))
	for _, window := range windows {
		attribution, found, resolveErr := s.ResolveDeviceAt(ctx, DomainObservation{IP: window.IP, Timestamp: window.LastObservedAt.Format(time.RFC3339Nano), SensorID: window.SensorID, CampusID: window.CampusID})
		if resolveErr != nil {
			return len(items), resolveErr
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
			return len(items), routerErr
		}
		key := strings.Join([]string{window.SensorID, window.CampusID, window.AccessDomain, window.IP}, "\x00")
		window.PhysicalDeviceIdentities = append([]string{}, currentIdentities[key]...)
		item, present := sharedaccess.AssessBehavior(window.ID, endpointID, window, router)
		if !present {
			continue
		}
		item.GenerationID = generationID
		item.KnownDevices = append([]sharedaccess.KnownDevice{}, referenceDevices[key]...)
		item.ReferenceDeviceCount24h = len(item.KnownDevices)
		item.KnownDeviceCount = item.DeviceLowerBound
		if len(window.AssociatedClients) > item.KnownDeviceCount {
			item.KnownDeviceCount = len(window.AssociatedClients)
			item.KnownDeviceBasis = "ieee1905_association_current"
			item.KnownDeviceWindow = "current"
		} else if item.StrongAnchor == "coexisting_device_identities" {
			item.KnownDeviceBasis = "coexisting_physical_identities"
			item.KnownDeviceWindow = "current"
		}
		items = append(items, item)
		windowsByID[item.ObservationID] = window
	}
	for _, item := range items {
		if err = s.writeSharedGatewayRouterEvidence(ctx, item); err != nil {
			return len(items), err
		}
		if bridge, ok := confirmedSharedBehaviorEvidence(windowsByID[item.ObservationID], item); ok {
			if err = s.WriteEvidence(ctx, []evidence.Evidence{bridge}); err != nil {
				return len(items), err
			}
		}
	}
	if err = s.persistSharedBehaviorGeneration(ctx, generationID, sensorID, windowStart, windowEnd, items); err != nil {
		return 0, err
	}
	_, _ = s.pg.db.ExecContext(ctx, `DELETE FROM shared_behavior_observations WHERE expires_at<now()`)
	state, _ := json.Marshal(map[string]any{"as_of": windowEnd, "generation_id": generationID, "window_start": windowStart, "rows": len(rows), "observations": len(items), "coverage_state": "verified", "stale": false, "coverage_blockers": coverageReasons})
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('shared-behavior',$1,now())
ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, state)
	return len(items), err
}

func (s *DBStore) recordFailedSharedBehaviorGeneration(ctx context.Context, sensorID string, now time.Time, runErr error) error {
	windowEnd := now.UTC().Add(-90 * time.Second).Truncate(5 * time.Minute)
	windowStart := windowEnd.Add(-10 * time.Minute)
	generationID := stableSharedBehaviorID("generation", sensorID, windowStart.Format(time.RFC3339Nano), windowEnd.Format(time.RFC3339Nano))
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO shared_behavior_generations(
 generation_id,sensor_id,window_start,window_end,coverage_state,coverage_blockers,active)
VALUES($1,$2,$3,$4,'failed',$5,false)
ON CONFLICT(generation_id) DO UPDATE SET coverage_state='failed',coverage_blockers=EXCLUDED.coverage_blockers,active=false`, generationID, sensorID, windowStart, windowEnd, []string{runErr.Error()})
	return err
}

func (s *DBStore) writeSharedGatewayRouterEvidence(ctx context.Context, item sharedaccess.BehaviorAssessment) error {
	if item.CoverageState != "verified" || item.Status != "confirmed" || item.StrongAnchor == "" || item.DeviceLowerBound < 2 || len(item.Conflicts) > 0 {
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
	if router.BrandReferenceOnly && !router.BrandAttribution {
		brand, series, model = "", "", ""
	}
	bridge := evidence.RouterEvidence{
		EvidenceID: evidenceID, AssessmentID: router.AssessmentID, Kind: "router_signal",
		EndpointID: router.EndpointID, IP: router.IP, MAC: router.MAC, Brand: brand,
		Series: series, Model: model, Role: "router", Source: "shared-behavior-materializer",
		BrandAttribution: router.BrandAttribution,
		SourceFamily:     "shared_gateway_behavior", SourceEventType: "shared_access_window",
		RawValue: strings.Join(behaviorGroups, ","), Strength: "strong", Score: score,
		RuleID: "verified-shared-gateway-role", RuleVersion: ruleVersion,
		Explanation:        "重复共现的多终端协议栈与独立设备身份表明该设备承担共享网关角色",
		AssociationQuality: router.AssociationQuality, Ambiguous: router.Ambiguous,
		FirstSeen: item.FirstSeen.UTC().Format(time.RFC3339Nano), LastSeen: item.LastSeen.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), EventIDs: append([]string{}, item.EventIDs...),
	}
	if len(bridge.EventIDs) > 20 {
		bridge.EventIDs = bridge.EventIDs[:20]
	}
	return s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: ruleVersion, ShadowMode: true, Evidence: []evidence.RouterEvidence{bridge}})
}
