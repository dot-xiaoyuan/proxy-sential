package policy

import "time"

// The blacklist is the admission counterpart of the whitelist: a matching
// subject is eligible for immediate enforcement. It deliberately reuses the
// whitelist entry model and matcher so scope, validity windows and matching
// semantics cannot diverge between the two lists. Only the list identity differs.
type BlacklistEntry = WhitelistEntry

func NormalizeBlacklist(entry *BlacklistEntry) error {
	return NormalizeWhitelist(entry)
}

// MatchBlacklist reports whether a subject matches an active blacklist entry.
func MatchBlacklist(entries []BlacklistEntry, subject WhitelistSubject, now time.Time) *BlacklistEntry {
	return MatchWhitelist(entries, subject, now)
}

// MatchAccountBlacklist mirrors MatchAccountWhitelist: the account itself or any
// of its active sessions may match.
func MatchAccountBlacklist(entries []BlacklistEntry, account string, sessions []Session, now time.Time) *BlacklistEntry {
	if match := MatchBlacklist(entries, WhitelistSubject{AccountID: account}, now); match != nil {
		return match
	}
	for _, session := range sessions {
		if session.AccountID != account || session.State(now) != "active" {
			continue
		}
		if match := MatchBlacklist(entries, WhitelistSubject{AccountID: account, IP: session.IP, MAC: session.MAC, GroupID: session.GroupID, CampusID: session.CampusID, AccessDomain: session.AccessDomain}, now); match != nil {
			return match
		}
	}
	return nil
}
