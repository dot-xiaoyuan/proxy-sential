package store

import (
	"sort"
	"time"

	"proxy-sentinel/internal/policy"
)

// sessionReconcileKind names one account_sessions change derived from a complete snapshot.
type sessionReconcileKind string

const (
	sessionReconcileInsert  sessionReconcileKind = "insert"
	sessionReconcileConfirm sessionReconcileKind = "confirm"
	sessionReconcileEnd     sessionReconcileKind = "end"
)

// sessionReconcileAction is one planned row change. Insert carries the full row;
// confirm and end only move the stored confirmation or end time.
type sessionReconcileAction struct {
	Kind      sessionReconcileKind
	SessionID string
	Row       policy.Session
	At        time.Time
}

// planSnapshotSessionReconcile turns one complete snapshot into account_sessions changes.
//
// Rules:
//   - A snapshot not newer than lastApplied is ignored.
//   - A member without a row is inserted as an open "reconcile" row, confirmed at the snapshot time.
//   - A member matching an open row only moves that row's confirmation time forward. Its
//     source, status and start time stay as the event path wrote them.
//   - A member matching an ended row is not reopened; the disagreement is counted as a conflict.
//   - An open in-scope row missing from the snapshot ends at the snapshot time, unless an
//     event confirmed it after the snapshot was taken.
//
// An empty snapshot plans nothing (see above). It returns the changes and the number of
// conflicts. It does not write anything.
func planSnapshotSessionReconcile(snapshot IdentitySnapshot, rows []policy.Session, lastApplied time.Time) ([]sessionReconcileAction, int) {
	observed := snapshot.ObservedAt
	if !observed.After(lastApplied) {
		return nil, 0
	}
	// An empty inventory is not evidence that every session ended: a failed source returns nothing.
	// Campus online counts never reach zero, so an empty snapshot changes nothing.
	if len(snapshot.Sessions) == 0 {
		return nil, 0
	}
	byID := make(map[string]policy.Session, len(rows))
	byKey := map[string][]policy.Session{}
	for _, row := range rows {
		byID[row.ID] = row
		if row.LoginKey != "" && sessionInScope(row, snapshot.IdentityScope) {
			byKey[row.LoginKey] = append(byKey[row.LoginKey], row)
		}
	}
	// One row per session ID is the storage contract. Dual-stack members share an ID, so keep the
	// first in (ID, IP) order and never plan two changes for the same row.
	members := append([]policy.Session(nil), snapshot.Sessions...)
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].ID != members[j].ID {
			return members[i].ID < members[j].ID
		}
		return members[i].IP < members[j].IP
	})
	var handled = make(map[string]bool, len(members))

	var actions []sessionReconcileAction
	conflicts := 0
	present := make(map[string]bool, len(members))
	for _, member := range members {
		if handled[member.ID] {
			continue
		}
		handled[member.ID] = true
		row, exists := byID[member.ID]
		if !exists && member.LoginKey != "" {
			// The same login can carry a new session ID after the online Redis run_id changed.
			// Match it only when exactly one row holds that login generation.
			candidates := byKey[member.LoginKey]
			if len(candidates) > 1 {
				conflicts++
				continue
			}
			if len(candidates) == 1 {
				row, exists = candidates[0], true
			}
		}
		if !exists {
			inserted := member
			inserted.Status = "reconcile"
			inserted.EndedAt = time.Time{}
			inserted.ConfirmedAt = observed
			actions = append(actions, sessionReconcileAction{Kind: sessionReconcileInsert, SessionID: member.ID, Row: inserted})
			continue
		}
		present[row.ID] = true
		switch {
		case !sessionInScope(row, snapshot.IdentityScope):
			conflicts++
		case !row.EndedAt.IsZero():
			conflicts++
		case row.ConfirmedAt.Before(observed):
			actions = append(actions, sessionReconcileAction{Kind: sessionReconcileConfirm, SessionID: row.ID, At: observed})
		}
	}

	ids := make([]string, 0, len(rows))
	openRows := make(map[string]policy.Session, len(rows))
	for _, row := range rows {
		if row.EndedAt.IsZero() && sessionInScope(row, snapshot.IdentityScope) {
			openRows[row.ID] = row
			ids = append(ids, row.ID)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		row := openRows[id]
		if present[id] || row.ConfirmedAt.After(observed) {
			continue
		}
		actions = append(actions, sessionReconcileAction{Kind: sessionReconcileEnd, SessionID: id, At: observed})
	}
	return actions, conflicts
}

// sessionInScope reports whether a stored or in-memory row belongs to the snapshot's collector.
// Rows written before sensor_id was stored carry an empty sensor and match by source, campus
// and access domain; a non-empty different sensor is another collector and never matches.
func sessionInScope(row policy.Session, scope IdentityScope) bool {
	if row.Source != scope.Source || row.CampusID != scope.CampusID || row.AccessDomain != scope.AccessDomain {
		return false
	}
	return row.SensorID == "" || row.SensorID == scope.SensorID
}

// loginKeyFromPayload identifies one login generation independently of the collector instance.
// The session ID also embeds the online Redis run_id, which changes when that Redis restarts.
func loginKeyFromPayload(payload map[string]any) string {
	source := stringFromMap(payload, "source_session_id")
	generation := stringFromMap(payload, "source_login_generation")
	if source == "" || generation == "" {
		return ""
	}
	return source + "|" + generation
}
