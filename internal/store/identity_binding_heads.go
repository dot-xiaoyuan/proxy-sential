package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

func bindingHeadID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// identityBindingGapFactor 是头部有效期相对存在窗口的倍数，必须大于 1。
// 头部有效期与“延长已有窗口”的阈值都按同一个窗口计算，若有效期恰好只有一个窗口，
// “头部仍然有效”与“观测比头部新一个窗口”的交集只剩一个点，延长路径实际无法触发：
// 现场长期 upd=0，连续在线的绑定每个窗口都要新插一行。取 2 表示同一存在窗口最多容忍
// 一个窗口的空档，空档超过两个窗口才另开一行。
const identityBindingGapFactor = 2

// bindingHeadCutoff 是仍可作为“同一个存在窗口”锚点的最老 last_seen。
// 基准取批内最新观测时间而不是 now：观测天生滞后 now，用 now 作基准又把有效期收窄一段，
// 同样会压掉延长路径。详见 identityBindingGapFactor。
func bindingHeadCutoff(anchor time.Time, window time.Duration) time.Time {
	return anchor.UTC().Add(-time.Duration(identityBindingGapFactor) * window)
}

func readBindingHeads(ctx context.Context, tx *sql.Tx, kind string, keys []string, window time.Duration, anchor time.Time) (map[string]storedWindow, error) {
	hashes := make([]string, len(keys))
	original := map[string]string{}
	for i, key := range keys {
		hashes[i] = bindingHeadID(key)
		original[hashes[i]] = key
	}
	rows, err := tx.QueryContext(ctx, `SELECT binding_key,event_id,last_seen FROM identity_binding_window_heads WHERE kind=$1 AND binding_key=ANY($2::text[])`, kind, hashes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]storedWindow{}
	cutoff := bindingHeadCutoff(anchor, window)
	for rows.Next() {
		var key string
		var value storedWindow
		if err = rows.Scan(&key, &value.EventID, &value.LastSeen); err != nil {
			return nil, err
		}
		if !value.LastSeen.Before(cutoff) {
			out[original[key]] = value
		}
	}
	return out, rows.Err()
}
func saveBindingHeads(ctx context.Context, tx *sql.Tx, kind string, observations []bindingObservation, ids []string, stored map[string]storedWindow, plan bindingPlan) error {
	keys, events, times := []string{}, []string{}, []time.Time{}
	for _, i := range plan.InsertIndexes {
		at, ok := parseTime(observations[i].LastSeen)
		if !ok {
			continue
		}
		keys = append(keys, bindingHeadID(observations[i].Key))
		events = append(events, ids[i])
		times = append(times, at)
	}
	byEvent := map[string]string{}
	for key, value := range stored {
		byEvent[value.EventID] = key
	}
	for i, id := range plan.ExtendEventID {
		keys = append(keys, bindingHeadID(byEvent[id]))
		events = append(events, id)
		times = append(times, plan.ExtendLastSeen[i])
	}
	if len(keys) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_binding_window_heads(kind,binding_key,event_id,last_seen) SELECT $1,k,e,t FROM unnest($2::text[],$3::text[],$4::timestamptz[]) AS v(k,e,t) ORDER BY k ON CONFLICT(kind,binding_key) DO UPDATE SET event_id=EXCLUDED.event_id,last_seen=EXCLUDED.last_seen WHERE identity_binding_window_heads.last_seen<=EXCLUDED.last_seen`, kind, keys, events, times)
	return err
}
