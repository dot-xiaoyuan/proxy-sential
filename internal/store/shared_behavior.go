package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
	Cursor        int
}

type SharedBehaviorPage struct {
	Items []sharedaccess.BehaviorAssessment `json:"items"`
	Page  Page                              `json:"page"`
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
	clauses := []string{"current=true", "expires_at>now()", "window_end>now()-interval '20 minutes'", "window_end<=now()"}
	if query.View != "" && query.View != "current" && query.View != "history" {
		return "", nil, fmt.Errorf("invalid shared behavior view")
	}
	if query.View == "history" {
		clauses = []string{"NOT (current AND rule_version='" + sharedaccess.BehaviorRuleVersion + "' AND expires_at>now() AND window_end>now()-interval '20 minutes' AND window_end<=now())"}
		// Old scores and router projections do not prove downstream devices.
		// Filter by evidence before choosing the newest historical episode.
		strong := `(status='confirmed' AND coverage_state='verified' AND COALESCE(observation->>'strong_anchor','') IN ('ieee1905_association','coexisting_device_models') AND CASE WHEN observation->>'device_lower_bound' ~ '^[0-9]{1,9}$' THEN (observation->>'device_lower_bound')::int ELSE 0 END>=2 AND COALESCE(NULLIF(observation->'conflicts','null'::jsonb),'[]'::jsonb)='[]'::jsonb)`
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
	if query.Limit > 100 || query.Cursor < 0 {
		return SharedBehaviorPage{}, fmt.Errorf("invalid shared behavior pagination")
	}
	where, args, err := sharedBehaviorWhere(query)
	if err != nil {
		return SharedBehaviorPage{}, err
	}
	args = append(args, query.Limit, query.Cursor)
	// Observations are immutable ten-minute windows. The operational list is a
	// gateway profile, so select the newest current window for each capture scope and IP
	// before applying user filters. Raw windows remain queryable through the
	// detail history and are never deleted by this view.
	latest := `SELECT DISTINCT ON(sensor_id,campus_id,access_domain,ip) *
 FROM shared_behavior_observations WHERE current=true AND rule_version='` + sharedaccess.BehaviorRuleVersion + `' AND expires_at>now()
 ORDER BY sensor_id,campus_id,access_domain,ip,last_seen DESC,observation_id DESC`
	if query.View == "history" {
		latest = `SELECT DISTINCT ON(sensor_id,campus_id,access_domain,ip,endpoint_id) * FROM shared_behavior_observations ` + where + ` ORDER BY sensor_id,campus_id,access_domain,ip,endpoint_id,last_seen DESC,observation_id DESC`
	}
	rows, err := s.db.QueryContext(ctx, `WITH latest AS (`+latest+`)
SELECT observation,count(*) OVER() FROM latest `+where+fmt.Sprintf(` ORDER BY confidence DESC,last_seen DESC,observation_id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return SharedBehaviorPage{}, err
	}
	defer rows.Close()
	page := SharedBehaviorPage{Items: []sharedaccess.BehaviorAssessment{}, Page: Page{Limit: query.Limit}}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw, &page.Page.Total); err != nil {
			return page, err
		}
		var item sharedaccess.BehaviorAssessment
		if err = json.Unmarshal(raw, &item); err != nil {
			return page, err
		}
		item.Current = query.View != "history"
		page.Items = append(page.Items, item)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if query.Cursor+len(page.Items) < page.Page.Total {
		next := fmt.Sprint(query.Cursor + len(page.Items))
		page.Page.NextCursor = &next
	}
	return page, nil
}

func (s *PostgresStore) GetSharedBehavior(ctx context.Context, id string) (SharedBehaviorDetail, bool, error) {
	var raw []byte
	var sensorID, campusID, accessDomain, ip string
	var current bool
	var windowStart, windowEnd, expires time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT observation,sensor_id,campus_id,access_domain,host(ip),current,window_start,window_end,expires_at FROM shared_behavior_observations WHERE observation_id=$1`, id).Scan(&raw, &sensorID, &campusID, &accessDomain, &ip, &current, &windowStart, &windowEnd, &expires); err != nil {
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
	result.Current = current && result.RuleVersion == sharedaccess.BehaviorRuleVersion && expires.After(now) && windowEnd.After(now.Add(-20*time.Minute)) && !windowEnd.After(now)
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
	return s.pg.GetSharedBehavior(ctx, id)
}
