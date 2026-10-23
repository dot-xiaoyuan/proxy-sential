package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type identityIntervalArchiveKey struct {
	Scope    string    `json:"scope_key"`
	Session  string    `json:"session_id"`
	IP       string    `json:"ip"`
	Hash     string    `json:"interval_hash"`
	Received time.Time `json:"first_received_at"`
}

func (s *DBStore) archiveIdentityIntervalBatch(ctx context.Context, now time.Time) (int, error) {
	result, err := s.pg.db.QueryContext(ctx, deviceRetentionReferences+` SELECT p.scope_key,p.session_id,p.ip,p.interval_hash,p.first_received_at,p.confirmed_at,p.document
 FROM identity_projection_intervals p WHERE p.first_received_at<$1 AND `+projectionRetentionProtected+` ORDER BY p.first_received_at,p.scope_key,p.session_id,p.ip,p.interval_hash LIMIT $2`, now.Add(-projectionHotRetention), projectionArchiveBatch)
	if err != nil {
		return 0, err
	}
	var keys []identityIntervalArchiveKey
	var archived []projectionArchiveRow
	for result.Next() {
		var k identityIntervalArchiveKey
		var r projectionArchiveRow
		if err = result.Scan(&k.Scope, &k.Session, &k.IP, &k.Hash, &k.Received, &r.ConfirmedAt, &r.Document); err != nil {
			result.Close()
			return 0, err
		}
		var scope IdentityScope
		var member AccountSession
		if err = json.Unmarshal([]byte(k.Scope), &scope); err != nil {
			result.Close()
			return 0, err
		}
		if err = json.Unmarshal(r.Document, &member); err != nil {
			result.Close()
			return 0, err
		}
		r.Source, r.SensorID, r.CampusID, r.AccessDomain = scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain
		r.SessionID, r.IP, r.AccountID = k.Session, k.IP, member.AccountID
		received := k.Received
		r.FirstReceivedAt = &received
		keys = append(keys, k)
		archived = append(archived, r)
	}
	err = result.Err()
	result.Close()
	if err != nil || len(keys) == 0 {
		return 0, err
	}
	body, err := json.Marshal(keys)
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(body)
	if err = s.ch.writeIdentityProjectionArchive(ctx, "projection-interval-"+hex.EncodeToString(digest[:]), archived, true); err != nil {
		return 0, fmt.Errorf("archive reused identity intervals: %w", err)
	}
	deleted, err := s.pg.db.ExecContext(ctx, deviceRetentionReferences+` DELETE FROM identity_projection_intervals p USING jsonb_to_recordset($1::jsonb) r(scope_key text,session_id text,ip text,interval_hash text,first_received_at timestamptz)
 WHERE p.scope_key=r.scope_key AND p.session_id=r.session_id AND p.ip=r.ip AND p.interval_hash=r.interval_hash AND p.first_received_at=r.first_received_at AND `+projectionRetentionProtected, body)
	if err != nil {
		return 0, err
	}
	n, _ := deleted.RowsAffected()
	return int(n), nil
}
