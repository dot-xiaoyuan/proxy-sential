package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"sort"
	"time"

	"proxy-sentinel/internal/policy"
)

// projectionMember is one presence interval of a snapshot member: it was listed in every projected
// snapshot of its scope from First until End (exclusive; zero while still open).
type projectionMember struct {
	Scope   IdentityScope
	Session policy.Session
	First   time.Time
	End     time.Time
}

type policySessionKey struct {
	scope  IdentityScope
	id, ip string
}

// policySessionsFromProjection rebuilds the policy sessions the per-snapshot computation produced,
// from the snapshot log and the projection's presence intervals instead of every snapshot document.
//
// Sessions of different (scope, session ID, IP) never interact in that computation, so each key is
// reconciled on its own, against only the snapshots that can change its state: the first and last
// snapshot of each presence, the snapshot after it, and the first two snapshots from each fact. The
// snapshots in between only add confirmations; they are carried as one confirmed range on the
// preceding boundary row. Coverage always comes from the whole log of the scope.
func policySessionsFromProjection(facts []policy.Session, log []snapshotMeta, members []projectionMember, at time.Time) []policy.Session {
	coverage := coverageFromLog(log, at)
	timeline := map[IdentityScope][]snapshotMeta{}
	for _, snapshot := range log {
		if !snapshot.ObservedAt.After(at) {
			timeline[snapshot.Scope] = append(timeline[snapshot.Scope], snapshot)
		}
	}
	for scope := range timeline {
		ordered := timeline[scope]
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].ObservedAt.Before(ordered[j].ObservedAt) })
	}
	factsByIP := map[policySessionKey][]policy.Session{}
	factsByKey := map[policySessionKey][]policy.Session{}
	membersByKey := map[policySessionKey][]projectionMember{}
	keys := []policySessionKey{}
	seen := map[policySessionKey]bool{}
	note := func(key policySessionKey) {
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	for _, fact := range facts {
		key := policySessionKey{scopeOf(fact), fact.ID, fact.IP}
		factsByKey[key] = append(factsByKey[key], fact)
		ipKey := policySessionKey{scope: key.scope, ip: key.ip}
		factsByIP[ipKey] = append(factsByIP[ipKey], fact)
		note(key)
	}
	for _, member := range members {
		key := policySessionKey{member.Scope, member.Session.ID, member.Session.IP}
		membersByKey[key] = append(membersByKey[key], member)
		note(key)
	}
	out := []policy.Session{}
	for _, key := range keys {
		keyLog := timeline[key.scope]
		conflict := identityCaptureConflict(factsByIP[policySessionKey{scope: key.scope, ip: key.ip}], keyLog, at, at)
		subset := keySnapshots(keyLog, factsByKey[key], membersByKey[key], key.scope)
		if conflict {
			// Preserve evidence but expose no unique owner across an unordered capture.
			ambiguous := reconcileIdentitySessions(factsByKey[key], subset, at)
			for i := range ambiguous {
				ambiguous[i].IdentityIssue = "identity_snapshot_capture_conflict"
				ambiguous[i].AccountID = ""
			}
			out = append(out, ambiguous...)
			continue
		}
		out = append(out, reconcileIdentitySessions(factsByKey[key], subset, at)...)
	}
	for i := range out {
		out[i].SourceCoverage = coverage[scopeOf(out[i])]
	}
	sortPolicySessions(out)
	return out
}

// keySnapshots selects the boundary snapshots of one key and the member rows present in them.
func keySnapshots(timeline []snapshotMeta, facts []policy.Session, members []projectionMember, scope IdentityScope) []IdentitySnapshot {
	if len(timeline) == 0 {
		return nil
	}
	first := func(at time.Time) int {
		return sort.Search(len(timeline), func(i int) bool { return !timeline[i].ObservedAt.Before(at) })
	}
	relevant := map[int]bool{}
	type presence struct {
		member     projectionMember
		start, end int
	}
	presences := []presence{}
	for _, member := range members {
		start := first(member.First)
		end := len(timeline) - 1
		if !member.End.IsZero() {
			end = first(member.End) - 1
		}
		if start > end {
			continue
		}
		relevant[start], relevant[end] = true, true
		if end+1 < len(timeline) {
			relevant[end+1] = true
		}
		presences = append(presences, presence{member, start, end})
	}
	// A fact applies at the first snapshot not before it. An end applied there can be followed by a
	// reopen at the next snapshot (an end at the same instant as a snapshot wins over it), so that
	// snapshot is a boundary too.
	for _, fact := range facts {
		if j := first(fact.ConfirmedAt); j < len(timeline) {
			relevant[j] = true
			if j+1 < len(timeline) {
				relevant[j+1] = true
			}
		}
	}
	rows := map[int][]policy.Session{}
	for _, p := range presences {
		boundaries := []int{}
		for j := p.start; j <= p.end; j++ {
			if relevant[j] {
				boundaries = append(boundaries, j)
			}
		}
		for n, j := range boundaries {
			snapshot := timeline[j]
			row := p.member.Session
			row.Status = "reconcile"
			row.StartedAt, row.ConfirmedAt, row.EndedAt = snapshot.ObservedAt, snapshot.ObservedAt, time.Time{}
			row.Confirmations = []time.Time{snapshot.ObservedAt}
			row.ConfirmedRanges = nil
			row.HeartbeatSeconds, row.ReconcileSeconds = snapshot.IntervalSeconds, snapshot.IntervalSeconds
			if n+1 < len(boundaries) && boundaries[n+1] > j+1 {
				last := timeline[boundaries[n+1]-1]
				row.ConfirmedRanges = []policy.IdentityCoverage{{From: timeline[j+1].ObservedAt, To: last.ObservedAt.Add(time.Duration(3*last.IntervalSeconds) * time.Second)}}
			}
			rows[j] = append(rows[j], row)
		}
	}
	indices := make([]int, 0, len(relevant))
	for j := range relevant {
		indices = append(indices, j)
	}
	sort.Ints(indices)
	subset := make([]IdentitySnapshot, 0, len(indices))
	for _, j := range indices {
		snapshot := timeline[j]
		subset = append(subset, IdentitySnapshot{IdentityScope: scope, SnapshotID: snapshot.SnapshotID, ObservedAt: snapshot.ObservedAt, IntervalSeconds: snapshot.IntervalSeconds, Sessions: rows[j]})
	}
	return subset
}

// policyIdentityWindow is how far back policy reads rebuild sessions, as before.
const policyIdentityWindow = 7 * 24 * time.Hour

// policySnapshotLogSQL reads projected snapshots inside the window plus the newest projected snapshot
// before it per scope, the same baseline the per-snapshot read used. $3 empty reads every scope.
const policySnapshotLogSQL = `SELECT source,sensor_id,campus_id,access_domain,snapshot_id,observed_at,interval_seconds FROM identity_snapshot_log
 WHERE projected AND observed_at BETWEEN $1 AND $2 AND ($3='' OR (campus_id=$3 AND access_domain=$4))
UNION ALL
SELECT source,sensor_id,campus_id,access_domain,snapshot_id,observed_at,interval_seconds FROM (
 SELECT DISTINCT ON(source,sensor_id,campus_id,access_domain) source,sensor_id,campus_id,access_domain,snapshot_id,observed_at,interval_seconds FROM identity_snapshot_log
 WHERE projected AND observed_at<$1 AND ($3='' OR (campus_id=$3 AND access_domain=$4))
 ORDER BY source,sensor_id,campus_id,access_domain,observed_at DESC) baseline`

// policyProjectionMembersSQL reads open members and members that ended inside the window. An ended
// member's confirmed_at is the snapshot that ended it.
const policyProjectionMembersSQL = `SELECT p.source,p.sensor_id,p.campus_id,p.access_domain,p.confirmed_at,p.document FROM account_identity_session_projection p
 WHERE COALESCE(p.document->>'ended_at','')='' AND ($1='' OR (p.campus_id=$1 AND p.access_domain=$2))
UNION ALL
SELECT p.source,p.sensor_id,p.campus_id,p.access_domain,p.confirmed_at,p.document FROM account_identity_session_projection p
 WHERE p.confirmed_at>=$3 AND COALESCE(p.document->>'ended_at','')<>'' AND ($1='' OR (p.campus_id=$1 AND p.access_domain=$2))`

// projectionPolicyInputs loads the snapshot timeline and presence intervals for policy reads.
func projectionPolicyInputs(ctx context.Context, db *sql.DB, at time.Time, campus, domain string) ([]snapshotMeta, []projectionMember, error) {
	since := at.Add(-policyIdentityWindow)
	logSQL := policySnapshotLogSQL
	delta := os.Getenv("PROXY_SENTINEL_IDENTITY_DELTA_ENABLED") == "true"
	if delta {
		logSQL = `SELECT l.*,r.capture_started_at FROM (` + policySnapshotLogSQL + `) l LEFT JOIN identity_delta_runs r USING(source,sensor_id,campus_id,access_domain,snapshot_id)`
	}
	rows, err := db.QueryContext(ctx, logSQL, since, at, campus, domain)
	if err != nil {
		return nil, nil, err
	}
	log := []snapshotMeta{}
	for rows.Next() {
		var v snapshotMeta
		fields := []any{&v.Scope.Source, &v.Scope.SensorID, &v.Scope.CampusID, &v.Scope.AccessDomain, &v.SnapshotID, &v.ObservedAt, &v.IntervalSeconds}
		var captured sql.NullTime
		if delta {
			fields = append(fields, &captured)
		}
		if err = rows.Scan(fields...); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if captured.Valid {
			v.CaptureStartedAt = captured.Time
		}
		log = append(log, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	membersSQL := policyProjectionMembersSQL
	if delta {
		membersSQL += ` UNION ALL SELECT r.scope_key::jsonb->>'source',r.scope_key::jsonb->>'sensor_id',r.scope_key::jsonb->>'campus_id',r.scope_key::jsonb->>'access_domain',r.confirmed_at,r.document FROM identity_projection_intervals r WHERE r.confirmed_at>=$3 AND ($1='' OR (r.scope_key::jsonb->>'campus_id'=$1 AND r.scope_key::jsonb->>'access_domain'=$2))`
	}
	rows, err = db.QueryContext(ctx, membersSQL, campus, domain, since)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	members := []projectionMember{}
	for rows.Next() {
		var scope IdentityScope
		var confirmed time.Time
		var raw []byte
		if err = rows.Scan(&scope.Source, &scope.SensorID, &scope.CampusID, &scope.AccessDomain, &confirmed, &raw); err != nil {
			return nil, nil, err
		}
		member, err := projectionMemberFromRow(scope, confirmed, raw)
		if err != nil {
			return nil, nil, err
		}
		members = append(members, member)
	}
	return log, members, rows.Err()
}

func projectionMemberFromRow(scope IdentityScope, confirmed time.Time, raw []byte) (projectionMember, error) {
	var document struct {
		AccountSession
		FirstConfirmedAt string `json:"first_confirmed_at"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return projectionMember{}, err
	}
	session := policySession(document.AccountSession)
	session.Source, session.SensorID, session.CampusID, session.AccessDomain = scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain
	member := projectionMember{Scope: scope, Session: session, First: confirmed}
	if document.EndedAt != "" {
		member.End = confirmed
	}
	if first, err := time.Parse(time.RFC3339Nano, document.FirstConfirmedAt); err == nil {
		member.First = first
	} else if !member.End.IsZero() {
		// An ended row written before first_confirmed_at existed has no known start: no presence.
		member.First = member.End
	}
	return member, nil
}

// A capture conflict affects only the interval before the next authoritative
// event or conflict-free full confirmation. Later events do not rewrite past
// attribution; callers evaluating a window still see any overlapping gap.
func identityCaptureConflict(facts []policy.Session, log []snapshotMeta, from, to time.Time) bool {
	conflictAt := func(snapshot snapshotMeta) bool {
		if snapshot.CaptureStartedAt.IsZero() {
			return false
		}
		for _, fact := range facts {
			if !fact.ConfirmedAt.Before(snapshot.CaptureStartedAt) && !fact.ConfirmedAt.After(snapshot.ObservedAt) {
				return true
			}
		}
		return false
	}
	for _, snapshot := range log {
		if snapshot.CaptureStartedAt.After(to) || !conflictAt(snapshot) {
			continue
		}
		var resolved time.Time
		for _, fact := range facts {
			if fact.ConfirmedAt.After(snapshot.ObservedAt) && (resolved.IsZero() || fact.ConfirmedAt.Before(resolved)) {
				resolved = fact.ConfirmedAt
			}
		}
		for _, next := range log {
			if next.ObservedAt.After(snapshot.ObservedAt) && !conflictAt(next) && (resolved.IsZero() || next.ObservedAt.Before(resolved)) {
				resolved = next.ObservedAt
			}
		}
		if resolved.IsZero() || from.Before(resolved) {
			return true
		}
	}
	return false
}
