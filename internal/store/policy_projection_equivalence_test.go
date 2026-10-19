package store

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
)

type equivalenceScenario struct {
	at        time.Time
	facts     []policy.Session
	full      []IdentitySnapshot // old input: every snapshot with every member
	log       []snapshotMeta     // new input: snapshot metadata
	members   []projectionMember // new input: one presence interval per member
	ips       []string
	timePoint []time.Time
}

func snapshotRowAt(id, account, ip string, observed time.Time) policy.Session {
	row := snapshotMember(id, account, ip)
	row.StartedAt, row.ConfirmedAt, row.Confirmations = observed, observed, []time.Time{observed}
	return row
}

// buildScenario creates snapshots every 30 minutes with outages, members with one continuous
// presence run each (the projection keeps one interval per member), and random login and logout
// facts for the same and for unrelated sessions.
func buildScenario(r *rand.Rand) equivalenceScenario {
	base := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	var times []time.Time
	cursor := base
	for len(times) < 20+r.Intn(30) {
		times = append(times, cursor)
		gap := 30 * time.Minute
		if r.Intn(9) == 0 {
			gap = time.Duration(2+r.Intn(4)) * time.Hour // source outage
		}
		cursor = cursor.Add(gap)
	}
	sc := equivalenceScenario{at: times[len(times)-1].Add(time.Duration(r.Intn(120)) * time.Minute)}
	for i, at := range times {
		sc.full = append(sc.full, IdentitySnapshot{IdentityScope: reconcileScope, SnapshotID: fmt.Sprintf("s%02d", i), ObservedAt: at, IntervalSeconds: 1800})
		sc.log = append(sc.log, snapshotMeta{Scope: reconcileScope, SnapshotID: fmt.Sprintf("s%02d", i), ObservedAt: at, IntervalSeconds: 1800})
	}
	nMembers := 1 + r.Intn(6)
	for m := 0; m < nMembers; m++ {
		id, account, ip := fmt.Sprintf("sess-%d", m), fmt.Sprintf("acct-%d", r.Intn(3)), fmt.Sprintf("10.0.0.%d", r.Intn(4))
		sc.ips = append(sc.ips, ip)
		start := r.Intn(len(times))
		end := start + r.Intn(len(times)-start) // last present index
		for i := start; i <= end; i++ {
			sc.full[i].Sessions = append(sc.full[i].Sessions, snapshotRowAt(id, account, ip, times[i]))
		}
		member := projectionMember{Scope: reconcileScope, Session: snapshotMember(id, account, ip), First: times[start]}
		if end+1 < len(times) {
			member.End = times[end+1]
		}
		sc.members = append(sc.members, member)
		// Events about the same session: logins and logouts at random times.
		for e := r.Intn(3); e > 0; e-- {
			at := base.Add(time.Duration(r.Intn(int(sc.at.Sub(base).Minutes()))) * time.Minute)
			fact := eventRow(id, account, ip, at)
			if r.Intn(2) == 0 {
				fact.Status, fact.EndedAt = "stop", at
			}
			sc.facts = append(sc.facts, fact)
		}
	}
	// Event-only sessions that no snapshot ever lists.
	for e := r.Intn(4); e > 0; e-- {
		ip := fmt.Sprintf("10.0.0.%d", r.Intn(4))
		at := base.Add(time.Duration(r.Intn(int(sc.at.Sub(base).Minutes()))) * time.Minute)
		sc.facts = append(sc.facts, eventRow(fmt.Sprintf("event-%d", e), fmt.Sprintf("acct-%d", r.Intn(3)), ip, at))
		sc.ips = append(sc.ips, ip)
	}
	for t := base.Add(-time.Hour); !t.After(sc.at); t = t.Add(7 * time.Minute) {
		sc.timePoint = append(sc.timePoint, t)
	}
	return sc
}

func activeByAccount(sessions []policy.Session, at time.Time) map[string]int {
	out := map[string]int{}
	for _, s := range sessions {
		if s.State(at) == "active" {
			out[s.AccountID]++
		}
	}
	return out
}

// The projection-based policy sessions must decide exactly as the per-snapshot computation did: the
// same attribution for every IP and the same active sessions per account, at every time point.
func TestProjectionPolicySessionsMatchPerSnapshotComputation(t *testing.T) {
	r := rand.New(rand.NewSource(20261019))
	for n := 0; n < 600; n++ {
		sc := buildScenario(r)
		old := reconcileIdentitySessions(sc.facts, sc.full, sc.at)
		got := policySessionsFromProjection(sc.facts, sc.log, sc.members, sc.at)
		for _, point := range sc.timePoint {
			for _, ip := range sc.ips {
				want := policy.Attribute(old, reconcileScope.CampusID, reconcileScope.AccessDomain, ip, point)
				have := policy.Attribute(got, reconcileScope.CampusID, reconcileScope.AccessDomain, ip, point)
				sort.Strings(want.SessionIDs)
				sort.Strings(have.SessionIDs)
				if want.State != have.State || want.AccountID != have.AccountID || !reflect.DeepEqual(want.SessionIDs, have.SessionIDs) {
					t.Fatalf("scenario %d ip %s at %s: old=%+v new=%+v", n, ip, point.Format("15:04"), want, have)
				}
			}
			if a, b := activeByAccount(old, point), activeByAccount(got, point); !reflect.DeepEqual(a, b) {
				t.Fatalf("scenario %d at %s: active old=%v new=%v", n, point.Format("15:04"), a, b)
			}
		}
	}
}

// The newest confirming snapshot is still the session's evidence, as the per-snapshot path reported.
func TestProjectionPolicySessionsKeepLatestSnapshotEvidence(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for n := 0; n < 200; n++ {
		sc := buildScenario(r)
		old := reconcileIdentitySessions(sc.facts, sc.full, sc.at)
		got := policySessionsFromProjection(sc.facts, sc.log, sc.members, sc.at)
		ids := func(ss []policy.Session) map[string][]string {
			out := map[string][]string{}
			for _, s := range ss {
				if s.State(sc.at) == "active" {
					out[s.ID+"@"+s.IP] = s.IdentitySnapshotIDs
				}
			}
			return out
		}
		if a, b := ids(old), ids(got); !reflect.DeepEqual(a, b) {
			t.Fatalf("scenario %d: snapshot evidence old=%v new=%v", n, a, b)
		}
	}
}
