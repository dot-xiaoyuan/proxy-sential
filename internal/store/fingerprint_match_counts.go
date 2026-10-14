package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

// Match counts measure successful recognition evaluations, not network packets.
// The ingest path performs no statistics writes. One minute of buffered counts
// may be lost on an abrupt process exit; historical evaluations are separate.
type fingerprintMatchBucket struct {
	Minute   int64  `json:"minute"`
	Source   string `json:"source"`
	Realtime int64  `json:"realtime"`
	History  int64  `json:"history"`
}
type fingerprintMatchMeter struct {
	mu         sync.Mutex
	buckets    map[string]fingerprintMatchBucket
	lastMinute int64
}

func (m *fingerprintMatchMeter) record(at time.Time, historical bool, matches []fingerprint.SourceMatch) {
	if len(matches) == 0 {
		return
	}
	minute := at.Unix() / 60
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.buckets == nil {
		m.buckets = map[string]fingerprintMatchBucket{}
	}
	if m.lastMinute != minute {
		for key, b := range m.buckets {
			if b.Minute < minute-1439 {
				delete(m.buckets, key)
			}
		}
		m.lastMinute = minute
	}
	seen := map[string]bool{}
	for _, match := range matches {
		identity := match.SourceID + "\x00" + match.RuleID
		if match.SourceID == "" || match.RuleID == "" || seen[identity] {
			continue
		}
		seen[identity] = true
		key := fmt.Sprintf("%d/%s", minute, match.SourceID)
		b := m.buckets[key]
		b.Minute = minute
		b.Source = match.SourceID
		if historical {
			b.History++
		} else {
			b.Realtime++
		}
		m.buckets[key] = b
	}
}
func (m *fingerprintMatchMeter) take() map[string]fingerprintMatchBucket {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.buckets
	m.buckets = nil
	return out
}
func mergeFingerprintCounts(dst, src map[string]fingerprintMatchBucket, at time.Time) {
	cutoff := at.Unix()/60 - 1439
	for k, b := range src {
		if b.Minute < cutoff {
			continue
		}
		old := dst[k]
		b.Realtime += old.Realtime
		b.History += old.History
		dst[k] = b
	}
	for k, b := range dst {
		if b.Minute < cutoff {
			delete(dst, k)
		}
	}
}
func (m *fingerprintMatchMeter) restore(batch map[string]fingerprintMatchBucket) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.buckets == nil {
		m.buckets = map[string]fingerprintMatchBucket{}
	}
	mergeFingerprintCounts(m.buckets, batch, time.Now())
}
func (s *DBStore) flushFingerprintMatchCounts(ctx context.Context) (err error) {
	batch := s.fingerprintMatches.take()
	if len(batch) == 0 {
		return nil
	}
	defer func() {
		if err != nil {
			s.fingerprintMatches.restore(batch)
		}
	}()
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('fingerprint-match-counts','{}',now()) ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT state FROM read_model_runtime_state WHERE name='fingerprint-match-counts' FOR UPDATE`).Scan(&raw); err != nil {
		return err
	}
	buckets := map[string]fingerprintMatchBucket{}
	if err = json.Unmarshal(raw, &buckets); err != nil {
		return err
	}
	mergeFingerprintCounts(buckets, batch, time.Now())
	raw, err = json.Marshal(buckets)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET state=$1,updated_at=now() WHERE name='fingerprint-match-counts'`, raw); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *DBStore) attachFingerprintMatchCounts(ctx context.Context, out map[string]any) error {
	var raw []byte
	if err := s.pg.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT state FROM read_model_runtime_state WHERE name='fingerprint-match-counts'),'{}'::jsonb)`).Scan(&raw); err != nil {
		return err
	}
	buckets := map[string]fingerprintMatchBucket{}
	if err := json.Unmarshal(raw, &buckets); err != nil {
		return err
	}
	totals := map[string]fingerprintMatchBucket{}
	for _, b := range buckets {
		if b.Minute < time.Now().Unix()/60-1439 {
			continue
		}
		v := totals[b.Source]
		v.Realtime += b.Realtime
		v.History += b.History
		totals[b.Source] = v
	}
	items, _ := out["items"].([]any)
	for _, value := range items {
		if item, ok := value.(map[string]any); ok {
			id, _ := item["source_id"].(string)
			v := totals[id]
			item["evaluation_match_count"] = v.Realtime + v.History
			item["realtime_match_count"] = v.Realtime
			item["history_match_count"] = v.History
			delete(totals, id)
		}
	}
	for id, v := range totals {
		items = append(items, map[string]any{"source_id": id, "match_count": 0, "endpoint_count": 0, "conflict_count": 0, "confirmed_count": 0, "evaluation_match_count": v.Realtime + v.History, "realtime_match_count": v.Realtime, "history_match_count": v.History})
	}
	out["items"] = items
	out["evaluation_count_semantics"] = "successful_recognition_evaluations_24h_minute_buckets"
	out["evaluation_flush_interval_seconds"] = 60
	return nil
}
