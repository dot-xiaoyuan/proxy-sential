package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/poison"
)

type DestinationTargetRule struct {
	RuleID             string   `json:"rule_id"`
	Name               string   `json:"name"`
	Enabled            bool     `json:"enabled"`
	BehaviorType       string   `json:"behavior_type"`
	TargetType         string   `json:"target_type"`
	Targets            []string `json:"targets"`
	WindowSeconds      int      `json:"window_seconds"`
	Threshold          int      `json:"threshold"`
	Direction          string   `json:"direction"`
	PushEnabled        bool     `json:"push_enabled"`
	PushWithoutAccount bool     `json:"push_without_account"`
	CreatedBy          string   `json:"created_by,omitempty"`
	UpdatedBy          string   `json:"updated_by,omitempty"`
	CreatedAt          string   `json:"created_at,omitempty"`
	UpdatedAt          string   `json:"updated_at,omitempty"`
}

type DestinationTargetFinding struct {
	FindingID          string   `json:"finding_id"`
	RuleID             string   `json:"rule_id"`
	RuleName           string   `json:"rule_name,omitempty"`
	SubjectIP          string   `json:"subject_ip"`
	AccountID          string   `json:"account_id,omitempty"`
	BehaviorType       string   `json:"behavior_type"`
	MatchedTargets     []string `json:"matched_targets"`
	UniqueDestinations int      `json:"unique_destinations"`
	HitCount           int      `json:"hit_count"`
	Direction          string   `json:"direction,omitempty"`
	WindowStart        string   `json:"window_start"`
	WindowEnd          string   `json:"window_end"`
	FirstSeen          string   `json:"first_seen"`
	LastSeen           string   `json:"last_seen"`
	Pushed             bool     `json:"pushed"`
	PushError          string   `json:"push_error,omitempty"`
	CreatedAt          string   `json:"created_at"`
}

const destinationTargetRuleColumns = `rule_id,name,enabled,behavior_type,target_type,to_json(targets)::text,window_seconds,threshold,direction,push_enabled,push_without_account,created_by,updated_by,to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),to_char(updated_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`

func scanDestinationTargetRule(scanner interface{ Scan(...any) error }) (DestinationTargetRule, error) {
	var rule DestinationTargetRule
	var targets string
	if err := scanner.Scan(&rule.RuleID, &rule.Name, &rule.Enabled, &rule.BehaviorType, &rule.TargetType, &targets, &rule.WindowSeconds, &rule.Threshold, &rule.Direction, &rule.PushEnabled, &rule.PushWithoutAccount, &rule.CreatedBy, &rule.UpdatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
		return DestinationTargetRule{}, err
	}
	// text[] arrives as a driver string; decode it as JSON for portability.
	rule.Targets = []string{}
	_ = json.Unmarshal([]byte(targets), &rule.Targets)
	return rule, nil
}

func (s *PostgresStore) ListDestinationTargetRules(ctx context.Context) ([]DestinationTargetRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+destinationTargetRuleColumns+` FROM destination_target_rules ORDER BY name,rule_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DestinationTargetRule{}
	for rows.Next() {
		item, err := scanDestinationTargetRule(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetDestinationTargetRule(ctx context.Context, id string) (DestinationTargetRule, error) {
	return scanDestinationTargetRule(s.db.QueryRowContext(ctx, `SELECT `+destinationTargetRuleColumns+` FROM destination_target_rules WHERE rule_id=$1`, id))
}

func (s *PostgresStore) UpsertDestinationTargetRule(ctx context.Context, rule poison.Rule, pushEnabled, pushWithoutAccount bool, actor string, creating bool) (DestinationTargetRule, error) {
	normalized := poison.NormalizeRule(rule)
	ruleID := normalized.RuleID
	if creating {
		_, err := s.db.ExecContext(ctx, `INSERT INTO destination_target_rules(rule_id,name,enabled,behavior_type,target_type,targets,window_seconds,threshold,direction,push_enabled,push_without_account,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`,
			ruleID, normalized.Name, normalized.Enabled, normalized.BehaviorType, normalized.TargetType, normalized.Targets, normalized.WindowSeconds, normalized.Threshold, normalized.Direction, pushEnabled, pushWithoutAccount, actor)
		if err != nil {
			return DestinationTargetRule{}, err
		}
	} else {
		result, err := s.db.ExecContext(ctx, `UPDATE destination_target_rules SET name=$2,enabled=$3,behavior_type=$4,target_type=$5,targets=$6,window_seconds=$7,threshold=$8,direction=$9,push_enabled=$10,push_without_account=$11,updated_by=$12,updated_at=now() WHERE rule_id=$1`,
			ruleID, normalized.Name, normalized.Enabled, normalized.BehaviorType, normalized.TargetType, normalized.Targets, normalized.WindowSeconds, normalized.Threshold, normalized.Direction, pushEnabled, pushWithoutAccount, actor)
		if err != nil {
			return DestinationTargetRule{}, err
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			return DestinationTargetRule{}, sql.ErrNoRows
		}
	}
	return s.GetDestinationTargetRule(ctx, ruleID)
}

func (s *PostgresStore) DeleteDestinationTargetRule(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM destination_target_rules WHERE rule_id=$1`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) WriteDestinationTargetFindings(ctx context.Context, findings []DestinationTargetFinding) error {
	for _, finding := range findings {
		targets, err := json.Marshal(finding.MatchedTargets)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO destination_target_findings(finding_id,rule_id,subject_ip,account_id,behavior_type,matched_targets,unique_destinations,hit_count,direction,window_start,window_end,first_seen,last_seen,pushed,push_error) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(finding_id) DO UPDATE SET hit_count=EXCLUDED.hit_count,unique_destinations=EXCLUDED.unique_destinations,matched_targets=EXCLUDED.matched_targets,last_seen=EXCLUDED.last_seen,window_start=EXCLUDED.window_start,window_end=EXCLUDED.window_end`,
			finding.FindingID, finding.RuleID, finding.SubjectIP, finding.AccountID, finding.BehaviorType, targets, finding.UniqueDestinations, finding.HitCount, finding.Direction, finding.WindowStart, finding.WindowEnd, finding.FirstSeen, finding.LastSeen, finding.Pushed, finding.PushError); err != nil {
			return err
		}
	}
	return nil
}

const destinationTargetFindingColumns = `finding_id,rule_id,subject_ip,account_id,behavior_type,matched_targets,unique_destinations,hit_count,direction,to_char(window_start,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),to_char(window_end,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),to_char(first_seen,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),to_char(last_seen,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),pushed,push_error,to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`

func (s *PostgresStore) ListDestinationTargetFindings(ctx context.Context, ruleID, subjectIP string, limit, offset int) ([]DestinationTargetFinding, int, error) {
	clauses := []string{}
	args := []any{}
	if ruleID != "" {
		args = append(args, ruleID)
		clauses = append(clauses, fmt.Sprintf("rule_id=$%d", len(args)))
	}
	if subjectIP != "" {
		args = append(args, subjectIP)
		clauses = append(clauses, fmt.Sprintf("subject_ip=$%d", len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM destination_target_findings`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, `SELECT `+destinationTargetFindingColumns+` FROM destination_target_findings`+where+fmt.Sprintf(` ORDER BY created_at DESC,finding_id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []DestinationTargetFinding{}
	for rows.Next() {
		var item DestinationTargetFinding
		var targets []byte
		if err := rows.Scan(&item.FindingID, &item.RuleID, &item.SubjectIP, &item.AccountID, &item.BehaviorType, &targets, &item.UniqueDestinations, &item.HitCount, &item.Direction, &item.WindowStart, &item.WindowEnd, &item.FirstSeen, &item.LastSeen, &item.Pushed, &item.PushError, &item.CreatedAt); err != nil {
			return nil, 0, err
		}
		item.MatchedTargets = []string{}
		_ = json.Unmarshal(targets, &item.MatchedTargets)
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (s *PostgresStore) MarkDestinationTargetFindingPushed(ctx context.Context, findingID, pushError string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE destination_target_findings SET pushed=($2=''),push_error=$2 WHERE finding_id=$1`, findingID, pushError)
	return err
}

// ListDestinationObservations returns per-(subject, destination) aggregates for
// the trailing window. Aggregating in ClickHouse keeps the result bounded by
// distinct pairs rather than by raw event volume.
func (s *ClickHouseStore) ListDestinationObservations(ctx context.Context, since time.Time, limit int) ([]poison.Observation, error) {
	if limit <= 0 {
		limit = 200000
	}
	sql := fmt.Sprintf(`SELECT subject_ip,dst_ip,count() AS hits,anyLast(proto) AS proto,anyLast(direction) AS direction,min(timestamp) AS first_seen,max(timestamp) AS last_seen FROM normalized_events PREWHERE timestamp >= toDateTime64('%s',6,'Asia/Shanghai') WHERE type IN ('flow','dns','tls','http','quic') AND subject_ip != '' AND dst_ip != '' GROUP BY subject_ip,dst_ip ORDER BY last_seen DESC LIMIT %d FORMAT JSONEachRow`, since.UTC().Format("2006-01-02 15:04:05.000000"), limit)
	data, err := s.activityFeatureQuery(ctx, sql)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		SubjectIP string `json:"subject_ip"`
		DstIP     string `json:"dst_ip"`
		Hits      uint64 `json:"hits"`
		Proto     string `json:"proto"`
		Direction string `json:"direction"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return nil, err
	}
	observations := make([]poison.Observation, 0, len(rows))
	for _, row := range rows {
		last, err := time.ParseInLocation("2006-01-02 15:04:05.000000", row.LastSeen, time.Local)
		if err != nil {
			continue
		}
		observations = append(observations, poison.Observation{SubjectIP: row.SubjectIP, DstIP: row.DstIP, Proto: row.Proto, Direction: row.Direction, Count: int(row.Hits), At: last})
	}
	return observations, nil
}

// DestinationTargetStore is the slice of storage the worker needs, so the worker
// can be tested without a full store implementation.
type DestinationTargetStore interface {
	ListDestinationTargetRules(ctx context.Context) ([]DestinationTargetRule, error)
	WriteDestinationTargetFindings(ctx context.Context, findings []DestinationTargetFinding) error
	ExpireDestinationTargetFindings(ctx context.Context, before time.Time) error
}

// ExpireDestinationTargetFindings keeps the finding table bounded; findings are
// an operational trail, not permanent evidence of record.
func (s *PostgresStore) ExpireDestinationTargetFindings(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM destination_target_findings WHERE created_at < $1`, before)
	return err
}
