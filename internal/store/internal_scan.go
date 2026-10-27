package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"proxy-sentinel/internal/netscan"
)

type InternalScanRule struct {
	CampusID string
	Config   netscan.Config
}

func (s *DBStore) ListInternalScanRules(ctx context.Context) ([]InternalScanRule, []netscan.Zone, error) {
	return s.pg.ListInternalScanRules(ctx)
}

func (s *PostgresStore) ListInternalScanRules(ctx context.Context) ([]InternalScanRule, []netscan.Zone, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT campus_id,excluded_source_cidrs::text,dense_hosts,dense_attempts,dense_consecutive,dense_failure_ratio,sparse_zones,sparse_ports,sparse_thin_ratio,sparse_failure_ratio FROM internal_scan_rules WHERE enabled=true ORDER BY campus_id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var rules []InternalScanRule
	for rows.Next() {
		var r InternalScanRule
		var excluded string
		if err := rows.Scan(&r.CampusID, &excluded, &r.Config.DenseHosts, &r.Config.DenseAttempts, &r.Config.DenseConsecutive, &r.Config.DenseFailureRatio, &r.Config.SparseZones, &r.Config.SparsePorts, &r.Config.SparseThinRatio, &r.Config.SparseFailureRatio); err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal([]byte(excluded), &r.Config.ExcludedSourceCIDRs); err != nil {
			return nil, nil, err
		}
		for _, cidr := range r.Config.ExcludedSourceCIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return nil, nil, fmt.Errorf("invalid excluded source CIDR for %s: %w", r.CampusID, err)
			}
		}
		r.Config.Enabled = true
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(rules) == 0 {
		return nil, nil, nil
	}
	zoneRows, err := s.db.QueryContext(ctx, `SELECT network_zone_id,campus_id,cidrs::text FROM network_zones WHERE enabled=true ORDER BY campus_id,network_zone_id`)
	if err != nil {
		return nil, nil, err
	}
	defer zoneRows.Close()
	var zones []netscan.Zone
	for zoneRows.Next() {
		var id, campus, raw string
		if err := zoneRows.Scan(&id, &campus, &raw); err != nil {
			return nil, nil, err
		}
		var cidrs []string
		if err := json.Unmarshal([]byte(raw), &cidrs); err != nil {
			return nil, nil, err
		}
		for _, cidr := range cidrs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return nil, nil, fmt.Errorf("invalid network zone CIDR for %s: %w", id, err)
			}
			zones = append(zones, netscan.Zone{ID: id + ":" + cidr, CampusID: campus, CIDR: cidr})
		}
	}
	return rules, zones, zoneRows.Err()
}

// ListInternalScanAttempts fails closed on truncation; a newest-N sample cannot
// establish complete target and failure ratios for a window.
func (s *DBStore) ListInternalScanAttempts(ctx context.Context, since time.Time, campuses []string, limit int) ([]netscan.Attempt, error) {
	return s.ch.ListInternalScanAttempts(ctx, since, campuses, limit)
}

func (s *ClickHouseStore) ListInternalScanAttempts(ctx context.Context, since time.Time, campuses []string, limit int) ([]netscan.Attempt, error) {
	if limit <= 0 {
		limit = 200000
	}
	if len(campuses) == 0 {
		return nil, nil
	}
	quoted := make([]string, 0, len(campuses))
	for _, campus := range campuses {
		quoted = append(quoted, chQuote(campus))
	}
	sql := fmt.Sprintf(`SELECT sensor_id,campus_id,event_id,subject_ip AS source_ip,dst_ip AS destination_ip,dst_port,toUnixTimestamp64Milli(timestamp) AS at_ms,JSONExtractString(flow_json,'connection_id') AS connection_id,JSONExtractString(payload_json,'state') AS state FROM normalized_events PREWHERE timestamp>=parseDateTime64BestEffort(%s,6) WHERE type='flow' AND sensor_id!='' AND campus_id IN (%s) AND subject_ip!='' AND subject_ip=src_ip AND dst_ip!='' ORDER BY timestamp DESC,event_id LIMIT %d FORMAT JSONEachRow`, chQuote(since.UTC().Format(time.RFC3339Nano)), strings.Join(quoted, ","), limit+1)
	data, err := s.activityFeatureQuery(ctx, sql)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		SensorID        string `json:"sensor_id"`
		CampusID        string `json:"campus_id"`
		EventID         string `json:"event_id"`
		SourceIP        string `json:"source_ip"`
		DestinationIP   string `json:"destination_ip"`
		DestinationPort int    `json:"dst_port"`
		AtMS            int64  `json:"at_ms"`
		ConnectionID    string `json:"connection_id"`
		State           string `json:"state"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return nil, err
	}
	if len(rows) > limit {
		return nil, fmt.Errorf("internal scan input truncated at %d flow events", limit)
	}
	attempts := make([]netscan.Attempt, 0, len(rows))
	for _, r := range rows {
		state := netscan.Unknown
		switch strings.ToUpper(strings.TrimSpace(r.State)) {
		case "S0", "REJ":
			state = netscan.Failed
		case "SF", "S1", "ESTABLISHED", "CLOSED":
			state = netscan.Succeeded
		}
		attempts = append(attempts, netscan.Attempt{SensorID: r.SensorID, CampusID: r.CampusID, EventID: r.EventID, ConnectionID: r.ConnectionID, SourceIP: r.SourceIP, DestinationIP: r.DestinationIP, DestinationPort: r.DestinationPort, State: state, At: time.UnixMilli(r.AtMS).UTC()})
	}
	return attempts, nil
}

func InternalScanFindingID(f netscan.Finding) string {
	bucket := 5 * time.Minute
	if f.Mode == netscan.Sparse {
		bucket = 10 * time.Minute
	}
	zoneKey := ""
	if f.Mode == netscan.Dense {
		zoneKey = strings.Join(f.ZoneIDs, ",")
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{string(f.Mode), f.SensorID, f.CampusID, f.SourceIP, zoneKey, f.WindowEnd.UTC().Truncate(bucket).Format(time.RFC3339)}, "\x00")))
	return "scan-" + hex.EncodeToString(sum[:16])
}

func (s *DBStore) WriteInternalScanFindings(ctx context.Context, findings []netscan.Finding) error {
	return s.pg.WriteInternalScanFindings(ctx, findings)
}

func (s *DBStore) WriteInternalScanRun(ctx context.Context, at time.Time, status, reason string, flows, findings int) error {
	return s.pg.WriteInternalScanRun(ctx, at, status, reason, flows, findings)
}

func (s *PostgresStore) WriteInternalScanRun(ctx context.Context, at time.Time, status, reason string, flows, findings int) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO internal_scan_runs(run_at,status,reason,flow_count,finding_count) VALUES($1,$2,$3,$4,$5) ON CONFLICT(run_at) DO UPDATE SET status=EXCLUDED.status,reason=EXCLUDED.reason,flow_count=EXCLUDED.flow_count,finding_count=EXCLUDED.finding_count`, at.Truncate(time.Minute), status, reason, flows, findings)
	if err != nil {
		return err
	}
	// These operational records are bounded; the underlying evidence follows its
	// independent retention and case-protection rules.
	if _, err = s.db.ExecContext(ctx, `DELETE FROM internal_scan_runs WHERE run_at < $1`, at.Add(-7*24*time.Hour)); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM internal_scan_findings WHERE created_at < $1`, at.Add(-7*24*time.Hour))
	return err
}

func (s *PostgresStore) WriteInternalScanFindings(ctx context.Context, findings []netscan.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, f := range findings {
		details, err := json.Marshal(f)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO internal_scan_findings(finding_id,campus_id,sensor_id,source_ip,mode,window_start,window_end,zone_count,destination_count,longest_consecutive,attempt_count,failed_count,succeeded_count,unknown_count,details) VALUES($1,$2,$3,$4::inet,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(finding_id) DO UPDATE SET window_start=EXCLUDED.window_start,window_end=EXCLUDED.window_end,zone_count=EXCLUDED.zone_count,destination_count=EXCLUDED.destination_count,longest_consecutive=EXCLUDED.longest_consecutive,attempt_count=EXCLUDED.attempt_count,failed_count=EXCLUDED.failed_count,succeeded_count=EXCLUDED.succeeded_count,unknown_count=EXCLUDED.unknown_count,details=EXCLUDED.details`, InternalScanFindingID(f), f.CampusID, f.SensorID, f.SourceIP, string(f.Mode), f.WindowStart, f.WindowEnd, len(f.ZoneIDs), f.UniqueDestinations, f.LongestConsecutive, f.Attempts, f.Failed, f.Succeeded, f.Unknown, details)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
