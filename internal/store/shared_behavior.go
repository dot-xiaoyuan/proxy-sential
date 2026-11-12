package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

type SharedBehaviorQuery struct {
	View          string
	HistoryBasis  string
	Keyword       string
	IP            string
	Status        string
	CoverageState string
	ConfidenceMin *int
	Limit         int
	Cursor        string
}

type SharedBehaviorPage struct {
	Items []sharedaccess.BehaviorAssessment `json:"items"`
	Page  SharedBehaviorCursorPage          `json:"page"`
}

type SharedBehaviorCursorPage struct {
	Limit      int     `json:"limit"`
	NextCursor *string `json:"next_cursor"`
	HasMore    bool    `json:"has_more"`
}

type sharedBehaviorCursor struct {
	At    time.Time `json:"at"`
	ID    string    `json:"id"`
	Scope string    `json:"scope"`
}

func sharedBehaviorCursorScope(query SharedBehaviorQuery) string {
	copy := query
	copy.Limit = 0
	copy.Cursor = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func decodeSharedBehaviorCursor(value, scope string) (sharedBehaviorCursor, error) {
	if len(value) > 2048 {
		return sharedBehaviorCursor{}, fmt.Errorf("invalid shared behavior cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return sharedBehaviorCursor{}, fmt.Errorf("invalid shared behavior cursor")
	}
	var cursor sharedBehaviorCursor
	if err = json.Unmarshal(raw, &cursor); err != nil || cursor.At.IsZero() || cursor.ID == "" || cursor.Scope != scope {
		return sharedBehaviorCursor{}, fmt.Errorf("invalid shared behavior cursor")
	}
	return cursor, nil
}

type SharedBehaviorHistory struct {
	Status        string    `json:"status"`
	Confidence    int       `json:"confidence"`
	SignalGroups  []string  `json:"signal_groups"`
	CoverageState string    `json:"coverage_state"`
	RuleVersion   string    `json:"rule_version"`
	ObservedAt    time.Time `json:"observed_at"`
	CreatedAt     time.Time `json:"created_at"`
}

type SharedBehaviorDetail struct {
	sharedaccess.BehaviorAssessment
	History []SharedBehaviorHistory `json:"history"`
}

type SharedBehaviorReader interface {
	ListSharedBehavior(context.Context, SharedBehaviorQuery) (SharedBehaviorPage, error)
	GetSharedBehavior(context.Context, string) (SharedBehaviorDetail, bool, error)
}

func sharedBehaviorWhere(query SharedBehaviorQuery) (string, []any, error) {
	clauses := []string{"current=true", "rule_version='" + sharedaccess.BehaviorRuleVersion + "'", "expires_at>now()", "window_end>now()-interval '20 minutes'", "window_end<=now()", "COALESCE(observation->'signal_groups','[]'::jsonb) ? 'ieee1905_association'", "generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=shared_behavior_observations.sensor_id AND c.state='active'),'')"}
	if query.View != "" && query.View != "current" && query.View != "history" {
		return "", nil, fmt.Errorf("invalid shared behavior view")
	}
	if query.View == "history" {
		clauses = []string{"NOT (current AND rule_version='" + sharedaccess.BehaviorRuleVersion + "' AND expires_at>now() AND window_end>now()-interval '20 minutes' AND window_end<=now() AND COALESCE(observation->'signal_groups','[]'::jsonb) ? 'ieee1905_association')"}
		// Old scores and router projections do not prove downstream devices.
		// Filter by evidence before choosing the newest historical episode.
		strong := `(status IN ('confirmed','candidate') AND coverage_state='verified' AND COALESCE(observation->>'strong_anchor','') ='ieee1905_association' AND CASE WHEN observation->>'device_lower_bound' ~ '^[0-9]{1,9}$' THEN (observation->>'device_lower_bound')::int ELSE 0 END>=2 AND COALESCE(NULLIF(observation->'conflicts','null'::jsonb),'[]'::jsonb)='[]'::jsonb)`
		switch query.HistoryBasis {
		case "", "shared":
			clauses = append(clauses, strong)
		case "clues":
			clauses = append(clauses, "NOT "+strong)
		default:
			return "", nil, fmt.Errorf("invalid historical evidence basis")
		}
	} else if query.HistoryBasis != "" {
		return "", nil, fmt.Errorf("historical evidence basis requires history view")
	}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if value := strings.TrimSpace(query.Keyword); value != "" {
		args = append(args, value)
		placeholder := fmt.Sprintf("$%d", len(args))
		clauses = append(clauses, `(observation_id ILIKE '%'||`+placeholder+`||'%' OR host(ip) ILIKE '%'||`+placeholder+`||'%' OR endpoint_id ILIKE '%'||`+placeholder+`||'%' OR observation->'router'->>'brand' ILIKE '%'||`+placeholder+`||'%' OR observation->'router'->>'model' ILIKE '%'||`+placeholder+`||'%')`)
	}
	if value := strings.TrimSpace(query.IP); value != "" {
		if netIP := strings.TrimSpace(value); netIP != "" {
			add(`ip=$%d::inet`, netIP)
		}
	}
	if value := strings.TrimSpace(query.Status); value != "" {
		if value != "candidate" && value != "likely" && value != "confirmed" {
			return "", nil, fmt.Errorf("invalid shared behavior status")
		}
		add(`status=$%d`, value)
		if value == "confirmed" && query.View != "history" {
			clauses = append(clauses, "COALESCE(observation->>'strong_anchor','')<>''")
		}
	}
	if value := strings.TrimSpace(query.CoverageState); value != "" {
		if value != "verified" && value != "partial" && value != "unknown" {
			return "", nil, fmt.Errorf("invalid coverage state")
		}
		add(`coverage_state=$%d`, value)
	}
	if query.ConfidenceMin != nil {
		if *query.ConfidenceMin < 0 || *query.ConfidenceMin > 100 {
			return "", nil, fmt.Errorf("invalid minimum confidence")
		}
		add(`confidence>=$%d`, *query.ConfidenceMin)
	}
	return "WHERE " + strings.Join(clauses, " AND "), args, nil
}

func (s *PostgresStore) ListSharedBehavior(ctx context.Context, query SharedBehaviorQuery) (SharedBehaviorPage, error) {
	if query.Limit <= 0 {
		query.Limit = 20
	}
	if query.Limit > 100 {
		return SharedBehaviorPage{}, fmt.Errorf("invalid shared behavior pagination")
	}
	where, args, err := sharedBehaviorWhere(query)
	if err != nil {
		return SharedBehaviorPage{}, err
	}
	if query.Cursor != "" {
		cursor, cursorErr := decodeSharedBehaviorCursor(query.Cursor, sharedBehaviorCursorScope(query))
		if cursorErr != nil {
			return SharedBehaviorPage{}, cursorErr
		}
		args = append(args, cursor.At, cursor.ID)
		where += fmt.Sprintf(" AND (last_seen,observation_id)<($%d,$%d)", len(args)-1, len(args))
	}
	args = append(args, query.Limit+1)
	// current is maintained as one row per gateway. Historical observations
	// retain their immutable windows; both views read a bounded index page.
	rows, err := s.db.QueryContext(ctx, `SELECT observation,last_seen,observation_id FROM shared_behavior_observations `+where+fmt.Sprintf(` ORDER BY last_seen DESC,observation_id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return SharedBehaviorPage{}, err
	}
	defer rows.Close()
	page := SharedBehaviorPage{Items: []sharedaccess.BehaviorAssessment{}, Page: SharedBehaviorCursorPage{Limit: query.Limit}}
	var lastAt time.Time
	var lastID string
	for rows.Next() {
		var raw []byte
		var at time.Time
		var id string
		if err = rows.Scan(&raw, &at, &id); err != nil {
			return page, err
		}
		if len(page.Items) == query.Limit {
			page.Page.HasMore = true
			break
		}
		var item sharedaccess.BehaviorAssessment
		if err = json.Unmarshal(raw, &item); err != nil {
			return page, err
		}
		item.Current = query.View != "history"
		page.Items = append(page.Items, item)
		lastAt, lastID = at, id
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if page.Page.HasMore {
		raw, _ := json.Marshal(sharedBehaviorCursor{At: lastAt, ID: lastID, Scope: sharedBehaviorCursorScope(query)})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.Page.NextCursor = &next
	}
	return page, nil
}

func (s *PostgresStore) GetSharedBehavior(ctx context.Context, id string) (SharedBehaviorDetail, bool, error) {
	var raw []byte
	var sensorID, campusID, accessDomain, ip string
	var current bool
	var windowStart, windowEnd, expires time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT observation,sensor_id,campus_id,access_domain,host(ip),
 current AND generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=o.sensor_id AND c.state='active'),''),
 window_start,window_end,expires_at FROM shared_behavior_observations o WHERE observation_id=$1`, id).Scan(&raw, &sensorID, &campusID, &accessDomain, &ip, &current, &windowStart, &windowEnd, &expires); err != nil {
		if err == sql.ErrNoRows {
			return SharedBehaviorDetail{}, false, nil
		}
		return SharedBehaviorDetail{}, false, err
	}
	var result SharedBehaviorDetail
	if err := json.Unmarshal(raw, &result.BehaviorAssessment); err != nil {
		return SharedBehaviorDetail{}, false, err
	}
	result.WindowStart, result.WindowEnd, result.ExpiresAt = windowStart.UTC(), windowEnd.UTC(), expires.UTC()
	now := time.Now().UTC()
	result.Current = slices.Contains(result.SignalGroups, "ieee1905_association") && current && result.RuleVersion == sharedaccess.BehaviorRuleVersion && expires.After(now) && windowEnd.After(now.Add(-20*time.Minute)) && !windowEnd.After(now)
	rows, err := s.db.QueryContext(ctx, `SELECT h.status,h.confidence,array_to_json(h.signal_groups),h.coverage_state,h.rule_version,h.observed_at,h.created_at
FROM shared_behavior_observation_history h
JOIN shared_behavior_observations o ON o.observation_id=h.observation_id
WHERE o.sensor_id=$1 AND o.campus_id=$2 AND o.access_domain=$3 AND o.ip=$4::inet
ORDER BY h.observed_at DESC,h.history_id DESC LIMIT 200`, sensorID, campusID, accessDomain, ip)
	if err != nil {
		return SharedBehaviorDetail{}, false, err
	}
	defer rows.Close()
	result.History = []SharedBehaviorHistory{}
	for rows.Next() {
		var item SharedBehaviorHistory
		var signalGroups []byte
		if err = rows.Scan(&item.Status, &item.Confidence, &signalGroups, &item.CoverageState, &item.RuleVersion, &item.ObservedAt, &item.CreatedAt); err != nil {
			return SharedBehaviorDetail{}, false, err
		}
		if err = json.Unmarshal(signalGroups, &item.SignalGroups); err != nil {
			return SharedBehaviorDetail{}, false, err
		}
		result.History = append(result.History, item)
	}
	return result, true, rows.Err()
}

func (s *DBStore) ListSharedBehavior(ctx context.Context, query SharedBehaviorQuery) (SharedBehaviorPage, error) {
	return s.pg.ListSharedBehavior(ctx, query)
}

func (s *DBStore) GetSharedBehavior(ctx context.Context, id string) (SharedBehaviorDetail, bool, error) {
	item, found, err := s.pg.GetSharedBehavior(ctx, id)
	if err != nil || found || !SharedObservationEnabled() {
		return item, found, err
	}
	return s.archivedSharedBehavior(ctx, id)
}
