package srunapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type Observation struct {
	ID         string     `json:"id"`
	Result     StepResult `json:"result"`
	StepFailed bool       `json:"step_failed"`
	RecordedAt time.Time  `json:"recorded_at"`
}
type ObservationPage struct {
	Items      []Observation `json:"items"`
	NextBefore string        `json:"next_before,omitempty"`
}

// Observations uses insertion order only. It does not choose a current action
// verdict from potentially concurrent observations. Scope comes from the stored
// action, never caller-supplied account/session query parameters.
func (j Journal) Observations(ctx context.Context, key, connector, account, session string, before int64, limit int) (ObservationPage, error) {
	page := ObservationPage{Items: []Observation{}}
	if j.DB == nil || key == "" || connector == "" || account == "" || session == "" || before < 0 || limit < 1 || limit > 100 {
		return page, fmt.Errorf("bounded observation query and full action scope required")
	}
	rows, err := j.DB.QueryContext(ctx, `SELECT o.observation_id,o.result,o.step_failed,o.recorded_at
 FROM native_action_observations o JOIN native_action_dispatch d USING(idempotency_key)
 WHERE o.idempotency_key=$1 AND d.intent->>'connector_id'=$2
 AND d.intent->'target'->>'account'=$3 AND d.intent->'target'->>'session_id'=$4
 AND ($5::bigint=0 OR o.observation_id<$5) ORDER BY o.observation_id DESC LIMIT $6`, key, connector, account, session, before, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var row Observation
		var id int64
		var body []byte
		if err = rows.Scan(&id, &body, &row.StepFailed, &row.RecordedAt); err != nil {
			return ObservationPage{}, err
		}
		if err = json.Unmarshal(body, &row.Result); err != nil {
			return ObservationPage{}, fmt.Errorf("invalid stored native observation")
		}
		row.ID = strconv.FormatInt(id, 10)
		page.Items = append(page.Items, row)
	}
	if err = rows.Err(); err != nil {
		return ObservationPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextBefore = page.Items[limit-1].ID
	}
	return page, nil
}
