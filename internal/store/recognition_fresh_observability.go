package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/recognitiondiag"
)

// This lane only observes receipts. It cannot enqueue work or touch old facts.
func (s *DBStore) runRecognitionFreshObserver(ctx context.Context) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 5*time.Second)
		n, err := s.observeFreshRecognition(work)
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Printf("fresh recognition observation failed: %v\n", err)
		}
		delay := time.Second
		if n == 100 && err == nil {
			delay = 100 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

const observeFreshRecognitionSQL = `WITH picked AS MATERIALIZED (
 SELECT accepted_month,epoch,scope_id,event_key,accepted_at,recognition_input,recognition_result,recognition_check_after
 FROM stream_discovery_receipts
 WHERE recognition_status IN ('processing','unattributed') AND recognition_check_after<=now()
 ORDER BY recognition_check_after,accepted_at LIMIT 100 FOR UPDATE SKIP LOCKED
), sized AS (
 SELECT *,sum(octet_length(recognition_input::text)+COALESCE(octet_length(recognition_result::text),0)) OVER(ORDER BY recognition_check_after,accepted_at,epoch,scope_id,event_key) AS bytes FROM picked
), resolved AS (
 SELECT v.*,CASE WHEN jsonb_array_length(COALESCE(v.recognition_input->'targets','[]'::jsonb))>0 THEN v.recognition_input
 ELSE v.recognition_input||jsonb_build_object('targets',ownership.targets) END AS input
 FROM sized v ` + recognitiondiag.TargetsLateralSQL + ` WHERE v.bytes<=262144
)
SELECT v.accepted_month,v.epoch,v.scope_id,v.event_key,v.accepted_at,v.input,COALESCE(v.recognition_result,'{}'::jsonb),clock_timestamp(),
 COALESCE((SELECT jsonb_agg(jsonb_build_object('endpoint_id',t.endpoint_id,'processed',j.processed_generation,
 'completed_at',j.processed_at,'timings',j.timings,'error',left(j.last_error,256),'summary',jsonb_build_object(
 'brand',r.summary->'brand','model',r.summary->'model','product_family',r.summary->'product_family','device_type',r.summary->'device_type','os_family',r.summary->'os_family',
 'conflict_dimensions',r.summary->'conflict_dimensions','recognition_conflict',r.conflict,'dimension_evidence',r.summary->'dimension_evidence')))
 FROM jsonb_to_recordset(v.input->'targets') t(endpoint_id text,generation bigint)
 JOIN endpoint_recognition_jobs j ON j.endpoint_id=t.endpoint_id
 LEFT JOIN endpoint_recognition_summary r ON r.endpoint_id=t.endpoint_id),'[]'::jsonb)
FROM resolved v`

type freshReceiptUpdate struct {
	Month      time.Time             `json:"accepted_month"`
	Epoch      string                `json:"epoch"`
	Scope      string                `json:"scope_id"`
	Key        string                `json:"event_key"`
	Input      recognitiondiag.Input `json:"input"`
	Status     string                `json:"status"`
	Completed  any                   `json:"completed_at"`
	Overdue    bool                  `json:"overdue"`
	CheckAfter any                   `json:"check_after"`
	Result     json.RawMessage       `json:"result"`
}

type freshJobSnapshot struct {
	recognitiondiag.Job
	Summary struct {
		Brand      string                          `json:"brand"`
		Model      string                          `json:"model"`
		Family     string                          `json:"product_family"`
		DeviceType string                          `json:"device_type"`
		OS         string                          `json:"os_family"`
		Conflict   bool                            `json:"recognition_conflict"`
		Conflicts  []string                        `json:"conflict_dimensions"`
		Evidence   []fingerprint.DimensionEvidence `json:"dimension_evidence"`
	} `json:"summary"`
}

// Count only this event's contributing evidence. A pre-existing OUI or another
// protocol's conclusion must never inflate the new protocol's funnel.
func freshSnapshotJob(snapshot freshJobSnapshot, event string) recognitiondiag.Job {
	job := snapshot.Job
	candidates := map[string]bool{}
	dimensions := map[string]bool{}
	for _, e := range snapshot.Summary.Evidence {
		matched := false
		for _, ref := range e.Refs {
			matched = matched || event != "" && ref.EventID == event
		}
		if !matched {
			continue
		}
		candidates[e.Layer+"\x00"+e.RuleID+"\x00"+e.Field] = true
		conflict := snapshot.Summary.Conflict && len(snapshot.Summary.Conflicts) == 0
		for _, dim := range snapshot.Summary.Conflicts {
			conflict = conflict || dim == e.Dimension
		}
		if conflict {
			job.Reason = "conflict"
			continue
		}
		value := ""
		switch e.Dimension {
		case "brand":
			value = snapshot.Summary.Brand
		case "model":
			value = snapshot.Summary.Model
		case "product_family":
			value = snapshot.Summary.Family
		case "device_type":
			value = snapshot.Summary.DeviceType
		case "os_family":
			value = snapshot.Summary.OS
		}
		if value != "" && strings.EqualFold(value, e.Value) && e.Confidence >= .8 {
			dimensions[e.Dimension] = true
		}
	}
	job.Candidates = len(candidates)
	job.Conclusions = len(dimensions)
	return job
}

func (s *DBStore) observeFreshRecognition(ctx context.Context) (int, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, observeFreshRecognitionSQL)
	if err != nil {
		return 0, err
	}
	updates := []freshReceiptUpdate{}
	for rows.Next() {
		var row freshReceiptUpdate
		var accepted, now time.Time
		var inputRaw, previousRaw, jobsRaw []byte
		if err = rows.Scan(&row.Month, &row.Epoch, &row.Scope, &row.Key, &accepted, &inputRaw, &previousRaw, &now, &jobsRaw); err != nil {
			break
		}
		if err = json.Unmarshal(inputRaw, &row.Input); err != nil {
			break
		}
		snapshots := []freshJobSnapshot{}
		if err = json.Unmarshal(jobsRaw, &snapshots); err != nil {
			break
		}
		jobs := make([]recognitiondiag.Job, 0, len(snapshots))
		for _, snapshot := range snapshots {
			jobs = append(jobs, freshSnapshotJob(snapshot, row.Input.EvidenceEvent))
		}
		d := recognitiondiag.Evaluate(row.Input, jobs, accepted, now)
		row.Status, row.Overdue = d.Status, d.Overdue
		if !d.CompletedAt.IsZero() {
			row.Completed = d.CompletedAt
		}
		if d.Status == "processing" || d.Status == "unattributed" {
			delay := 2 * time.Second
			if d.Status == "unattributed" {
				delay = 30 * time.Second
			}
			row.CheckAfter = now.Add(delay)
		}
		// Preserve the last observed processing error even after a successful retry.
		result := map[string]any{}
		if err = json.Unmarshal(previousRaw, &result); err != nil {
			break
		}
		result["candidates"], result["conclusions"] = d.Candidates, d.Conclusions
		if len(d.Timings) > 0 {
			result["timings"] = d.Timings
		}
		if d.Error != "" {
			result["last_error"] = d.Error
		}
		if row.Result, err = json.Marshal(result); err != nil {
			break
		}
		updates = append(updates, row)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	if len(updates) > 0 {
		raw, err := json.Marshal(updates)
		if err != nil {
			return 0, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE stream_discovery_receipts r SET recognition_input=v.input,recognition_status=v.status,
 recognition_completed_at=v.completed_at,recognition_overdue=v.overdue,recognition_check_after=v.check_after,recognition_result=v.result
 FROM jsonb_to_recordset($1::jsonb) v(accepted_month date,epoch text,scope_id text,event_key text,input jsonb,status text,completed_at timestamptz,overdue boolean,check_after timestamptz,result jsonb)
 WHERE r.accepted_month=v.accepted_month AND r.epoch=v.epoch AND r.scope_id=v.scope_id AND r.event_key=v.event_key`, raw)
		if err != nil {
			return 0, err
		}
	}
	return len(updates), tx.Commit()
}

type freshProtocolCount struct {
	Protocol     string  `json:"protocol"`
	Purpose      string  `json:"purpose"`
	Inputs       int64   `json:"inputs"`
	Parsed       int64   `json:"parsed"`
	Attributed   int64   `json:"attributed"`
	Features     int64   `json:"features"`
	Candidates   int64   `json:"candidates"`
	Conclusions  int64   `json:"conclusions"`
	Conflict     int64   `json:"conflict"`
	Processing   int64   `json:"processing"`
	Unattributed int64   `json:"unattributed"`
	Insufficient int64   `json:"insufficient"`
	Errors       int64   `json:"errors"`
	Overdue      int64   `json:"overdue"`
	Status       string  `json:"status"`
	Timed        int64   `json:"timed"`
	ReadMS       float64 `json:"read_and_prepare_ms"`
	LookupMS     float64 `json:"lookup_ms"`
	RulesMS      float64 `json:"rules_ms"`
	WriteMS      float64 `json:"write_ms"`
	ProcessP95MS float64 `json:"processing_upper_p95_ms"`
}

func (s *DBStore) refreshFreshRecognitionCoverage(ctx context.Context) error {
	rows, err := s.pg.db.QueryContext(ctx, `SELECT recognition_input->>'protocol',count(*),
 count(*) FILTER(WHERE (recognition_input->>'parsed')::boolean),
 count(*) FILTER(WHERE jsonb_array_length(COALESCE(recognition_input->'targets','[]'::jsonb))>0),
 count(*) FILTER(WHERE (recognition_input->>'features')::integer>0),
 count(*) FILTER(WHERE COALESCE((recognition_result->>'candidates')::integer,0)>0),
 count(*) FILTER(WHERE COALESCE((recognition_result->>'conclusions')::integer,0)>0),
 count(*) FILTER(WHERE recognition_status='conflict'),
 count(*) FILTER(WHERE recognition_status='processing'),
 count(*) FILTER(WHERE recognition_status IN ('unattributed','unattributed_expired')),
 count(*) FILTER(WHERE recognition_status IN ('no_features','insufficient_evidence')),
 count(*) FILTER(WHERE recognition_status IN ('parse_error','diagnostic_limit') OR recognition_result ? 'last_error'),
 count(*) FILTER(WHERE recognition_overdue OR (recognition_status IN ('processing','unattributed') AND accepted_at<now()-interval '5 seconds')),
 count(*) FILTER(WHERE recognition_result->'timings' IS NOT NULL),
 COALESCE(avg((recognition_result->'timings'->>'read_and_prepare_ms')::double precision),0),
 COALESCE(avg((recognition_result->'timings'->>'lookup_ms')::double precision),0),
 COALESCE(avg((recognition_result->'timings'->>'rules_ms')::double precision),0),
 COALESCE(avg((recognition_result->'timings'->>'write_ms')::double precision),0),
 COALESCE(percentile_cont(.95) WITHIN GROUP(ORDER BY extract(epoch FROM recognition_completed_at-accepted_at)*1000) FILTER(WHERE recognition_completed_at IS NOT NULL),0)
 FROM stream_discovery_receipts WHERE recognition_input IS NOT NULL AND accepted_at>=now()-interval '24 hours'
 GROUP BY recognition_input->>'protocol'`)
	if err != nil {
		return err
	}
	counts := map[string]freshProtocolCount{}
	for rows.Next() {
		var c freshProtocolCount
		if err = rows.Scan(&c.Protocol, &c.Inputs, &c.Parsed, &c.Attributed, &c.Features, &c.Candidates, &c.Conclusions, &c.Conflict, &c.Processing, &c.Unattributed, &c.Insufficient, &c.Errors, &c.Overdue, &c.Timed, &c.ReadMS, &c.LookupMS, &c.RulesMS, &c.WriteMS, &c.ProcessP95MS); err != nil {
			break
		}
		c.Status = "observed"
		counts[c.Protocol] = c
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	items := make([]freshProtocolCount, 0, len(recognitiondiag.Protocols))
	for _, p := range recognitiondiag.Protocols {
		c := counts[p.Name]
		c.Protocol, c.Purpose = p.Name, p.Purpose
		if c.Inputs == 0 {
			c.Status = "no_input"
		}
		items = append(items, c)
		delete(counts, p.Name)
	}
	// Retain unexpected actual protocol names instead of silently discarding them.
	for _, c := range counts {
		items = append(items, c)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return err
	}
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at)
 SELECT 'recognition-fresh-coverage',jsonb_build_object('status','ready','as_of',now(),'since',state->>'since','window','24h',
 'input_semantics','accepted_standard_discovery_events','completion_semantics','generation_commit_upper_bound','http_visibility','requires_authenticated_probe',
 'history_policy','excluded_without_backfill','items',$1::jsonb),now() FROM read_model_runtime_state WHERE name='recognition-fresh-cutoff'
 ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=EXCLUDED.updated_at`, raw)
	return err
}
