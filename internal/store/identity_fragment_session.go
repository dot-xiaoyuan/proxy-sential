package store

import (
	"sort"
	"strings"

	"proxy-sentinel/internal/normalized"
)

// Close wins over an open observation at the same timestamp. Older arrivals
// may extend the known interval, but cannot revert current session attributes.
const fragmentSessionNewerSQL = `(` + accountSessionMetadataNewerSQL + `)
 AND (COALESCE(NULLIF(EXCLUDED.policy_metadata->>'last_confirmed_at','')::timestamptz,'-infinity'::timestamptz)>COALESCE(NULLIF(account_sessions.policy_metadata->>'last_confirmed_at','')::timestamptz,'-infinity'::timestamptz)
 OR account_sessions.ended_at IS NULL OR EXCLUDED.ended_at IS NOT NULL)`

const fragmentSessionHistoryChangedSQL = `EXCLUDED.started_at < account_sessions.started_at
 OR EXCLUDED.identity_confidence > account_sessions.identity_confidence
 OR (EXCLUDED.ended_at IS NOT NULL AND (account_sessions.ended_at IS NULL OR EXCLUDED.ended_at > account_sessions.ended_at))`

var fragmentSessionUpsertSQL = buildFragmentSessionUpsertSQL()

// Reuse the input arrays and base schema; only durable fragment consumers use
// this ordering policy. Replace complete assignments, never column substrings.
func buildFragmentSessionUpsertSQL() string {
	statement := upsertAccountSessionsSQL
	replace := func(old, next string) {
		if strings.Count(statement, old) != 1 {
			panic("session SQL assignment drift: " + old)
		}
		statement = strings.Replace(statement, old, next, 1)
	}
	for _, column := range []string{"account_id", "endpoint_id", "ip", "mac", "access_id", "source", "raw_ref", "person_type", "department", "campus_id", "building_id", "network_zone_id", "ssid", "vlan", "ap", "nas_ip", "session_status"} {
		rhs := "EXCLUDED." + column
		if column == "raw_ref" {
			rhs = "account_sessions.raw_ref || EXCLUDED.raw_ref"
		} else if column != "account_id" && column != "endpoint_id" && column != "ip" && column != "mac" && column != "access_id" && column != "source" {
			rhs = "COALESCE(EXCLUDED." + column + ", account_sessions." + column + ")"
		}
		replace("  "+column+" = "+rhs+",", "  "+column+" = CASE WHEN "+fragmentSessionNewerSQL+" THEN "+rhs+" ELSE account_sessions."+column+" END,")
	}
	replace("  ended_at = COALESCE(EXCLUDED.ended_at, account_sessions.ended_at),", "  ended_at = GREATEST(EXCLUDED.ended_at, account_sessions.ended_at),")
	replace("  policy_metadata = CASE WHEN "+accountSessionMetadataNewerSQL+" THEN EXCLUDED.policy_metadata ELSE account_sessions.policy_metadata END,", "  policy_metadata = CASE WHEN "+fragmentSessionNewerSQL+" THEN EXCLUDED.policy_metadata ELSE account_sessions.policy_metadata END,")
	changed := "((" + fragmentSessionNewerSQL + ") AND (" + accountSessionValuesChangedSQL + ")) OR (" + fragmentSessionHistoryChangedSQL + ")"
	replace("  updated_at = CASE WHEN ("+accountSessionValuesChangedSQL+") THEN now() ELSE account_sessions.updated_at END", "  updated_at = CASE WHEN ("+changed+") THEN now() ELSE account_sessions.updated_at END")
	replace("WHERE ("+accountSessionValuesChangedSQL+")\n OR (("+accountSessionMetadataNewerSQL+") AND account_sessions.policy_metadata IS DISTINCT FROM EXCLUDED.policy_metadata)", "WHERE ("+changed+") OR (("+fragmentSessionNewerSQL+") AND account_sessions.policy_metadata IS DISTINCT FROM EXCLUDED.policy_metadata)")
	return statement
}

func fragmentCompatibilitySessions(events []normalized.Event) []AccountSession {
	ordered := append([]normalized.Event(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, _ := parseTime(ordered[i].Timestamp)
		b, _ := parseTime(ordered[j].Timestamp)
		if !a.Equal(b) {
			return a.Before(b)
		}
		// At equal time process the close last, matching the SQL merge policy.
		left := accountSessionFromFact(identityFactFromEvent(ordered[i])).EndedAt != ""
		right := accountSessionFromFact(identityFactFromEvent(ordered[j])).EndedAt != ""
		return !left && right
	})
	return BuildIdentityState(ordered).Sessions
}
