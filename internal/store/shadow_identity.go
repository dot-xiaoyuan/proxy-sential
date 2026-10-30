package store

import (
	"context"
	"time"
)

// GetAccountIdentityShadow serves the Kafka-backed identity shadow without
// touching the legacy account_sessions/IP-history joins. The shadow intentionally
// contains recent state, not the full historical profile.
func (s *DBStore) GetAccountIdentityShadow(ctx context.Context, accountID string, query Query) (AccountIdentityProfile, bool, error) {
	limit := query.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pg.db.QueryContext(ctx, `SELECT session_id,account_id,endpoint_id,ip,mac,source,vlan,nas_ip,session_status,
started_at,ended_at,last_confirmed_at,updated_at,identity_confidence
FROM identity_session_shadow WHERE account_id=$1 ORDER BY updated_at DESC LIMIT $2`, accountID, limit)
	if err != nil {
		return AccountIdentityProfile{}, false, err
	}
	defer rows.Close()
	profile := AccountIdentityProfile{AccountID: accountID, Summary: "Kafka identity shadow", Endpoints: []EndpointEntity{}, Sessions: []AccountSession{}}
	endpoints := map[string]EndpointEntity{}
	var first, last string
	for rows.Next() {
		var x shadowIdentitySession
		if err := rows.Scan(&x.SessionID, &x.AccountID, &x.EndpointID, &x.IP, &x.MAC, &x.Source, &x.VLAN, &x.NASIP, &x.Status,
			&x.StartedAt, &x.EndedAt, &x.LastConfirmedAt, &x.UpdatedAt, &x.Confidence); err != nil {
			return AccountIdentityProfile{}, false, err
		}
		session := x.accountSession()
		profile.Sessions = append(profile.Sessions, session)
		if x.EndpointID != "" {
			ep := endpoints[x.EndpointID]
			ep.EndpointID = x.EndpointID
			ep.PrimaryMAC = x.MAC
			ep.OwnerAccount = x.AccountID
			ep.EntityRole = "endpoint"
			ep.OwnershipClass = "account"
			ep.LastSeen = shadowTime(x.LastConfirmedAt)
			ep.FirstSeen = shadowTime(x.StartedAt)
			ep.IdentityConfidence = x.Confidence
			endpoints[x.EndpointID] = ep
		}
		first = shadowMin(first, shadowTime(x.StartedAt))
		last = shadowMax(last, shadowTime(x.LastConfirmedAt))
	}
	if err := rows.Err(); err != nil {
		return AccountIdentityProfile{}, false, err
	}
	if len(profile.Sessions) == 0 {
		return AccountIdentityProfile{}, false, nil
	}
	for _, ep := range endpoints {
		profile.Endpoints = append(profile.Endpoints, ep)
	}
	profile.FirstSeen = first
	profile.LastSeen = last
	profile.IPHistory, profile.AccessHistory = shadowHistory(profile.Sessions, "account")
	return profile, true, nil
}

// GetEndpointIdentityShadow serves endpoint current/session state from the
// Kafka shadow. Discovery and registration evidence stay on their existing
// readers until those projections are migrated.
func (s *DBStore) GetEndpointIdentityShadow(ctx context.Context, endpointID string, query Query) (EndpointIdentityProfile, bool, error) {
	limit := query.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pg.db.QueryContext(ctx, `SELECT session_id,account_id,endpoint_id,ip,mac,source,vlan,nas_ip,session_status,
started_at,ended_at,last_confirmed_at,updated_at,identity_confidence
FROM identity_session_shadow WHERE endpoint_id=$1 ORDER BY updated_at DESC LIMIT $2`, endpointID, limit)
	if err != nil {
		return EndpointIdentityProfile{}, false, err
	}
	defer rows.Close()
	profile := EndpointIdentityProfile{EndpointID: endpointID, Summary: "Kafka identity shadow", Sessions: []AccountSession{}, Accounts: []string{}}
	accounts := map[string]struct{}{}
	var first, last, primaryMAC, owner string
	seen := false
	for rows.Next() {
		var x shadowIdentitySession
		if err := rows.Scan(&x.SessionID, &x.AccountID, &x.EndpointID, &x.IP, &x.MAC, &x.Source, &x.VLAN, &x.NASIP, &x.Status,
			&x.StartedAt, &x.EndedAt, &x.LastConfirmedAt, &x.UpdatedAt, &x.Confidence); err != nil {
			return EndpointIdentityProfile{}, false, err
		}
		profile.Sessions = append(profile.Sessions, x.accountSession())
		if x.AccountID != "" {
			accounts[x.AccountID] = struct{}{}
		}
		if !seen || shadowTime(x.LastConfirmedAt) > last {
			if x.MAC != "" {
				primaryMAC = x.MAC
			}
			owner = x.AccountID
			last = shadowTime(x.LastConfirmedAt)
		}
		first = shadowMin(first, shadowTime(x.StartedAt))
		seen = true
	}
	if err := rows.Err(); err != nil {
		return EndpointIdentityProfile{}, false, err
	}
	if !seen {
		return EndpointIdentityProfile{}, false, nil
	}
	for account := range accounts {
		profile.Accounts = append(profile.Accounts, account)
	}
	profile.Endpoint = EndpointEntity{
		EndpointID: endpointID, PrimaryMAC: primaryMAC, OwnerAccount: owner,
		EntityRole: "endpoint", FirstSeen: first, LastSeen: last, IdentityConfidence: 0.95,
		Attributes: map[string]any{},
	}
	profile.FirstSeen = first
	profile.LastSeen = last
	profile.IPHistory, profile.AccessHistory = shadowHistory(profile.Sessions, "endpoint")
	return profile, true, nil
}

type shadowIdentitySession struct {
	SessionID, AccountID, EndpointID, IP, MAC, Source, VLAN, NASIP, Status string
	StartedAt, EndedAt, LastConfirmedAt, UpdatedAt                         *time.Time
	Confidence                                                             float64
}

func (x shadowIdentitySession) accountSession() AccountSession {
	return AccountSession{
		SessionID: x.SessionID, AccountID: x.AccountID, EndpointID: x.EndpointID,
		IP: x.IP, MAC: x.MAC, Source: x.Source, StartedAt: shadowTime(x.StartedAt),
		EndedAt: shadowTime(x.EndedAt), LastConfirmedAt: shadowTime(x.LastConfirmedAt),
		IdentityConfidence: x.Confidence, VLAN: x.VLAN, NASIP: x.NASIP, SessionStatus: x.Status,
	}
}

func shadowTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func shadowMin(a, b string) string {
	if a == "" || (b != "" && b < a) {
		return b
	}
	return a
}

func shadowMax(a, b string) string {
	if b > a {
		return b
	}
	return a
}

// shadowHistory derives bounded IP/access history from the shadow sessions.
// It is recent-window history, not the legacy full history table.
func shadowHistory(sessions []AccountSession, role string) ([]IdentityIPMACHistory, []IdentityAccessHistory) {
	ipIndex := map[string]int{}
	accessIndex := map[string]int{}
	ipHistory := []IdentityIPMACHistory{}
	accessHistory := []IdentityAccessHistory{}
	for _, session := range sessions {
		if session.IP != "" || session.MAC != "" {
			key := session.EndpointID + "|" + session.IP + "|" + session.MAC + "|" + session.Source
			if index, ok := ipIndex[key]; ok {
				item := &ipHistory[index]
				item.FirstSeen = shadowMin(item.FirstSeen, session.StartedAt)
				item.LastSeen = shadowMax(item.LastSeen, session.LastConfirmedAt)
				if len(item.EventIDsSample) < 5 {
					item.EventIDsSample = append(item.EventIDsSample, session.SessionID)
				}
			} else {
				ipIndex[key] = len(ipHistory)
				ipHistory = append(ipHistory, IdentityIPMACHistory{
					EventID: session.SessionID, EndpointID: session.EndpointID, AccountID: session.AccountID,
					EntityRole: role, IP: session.IP, MAC: session.MAC, Source: session.Source,
					FirstSeen: session.StartedAt, LastSeen: session.LastConfirmedAt,
					IdentityConfidence: session.IdentityConfidence, EventIDsSample: []string{session.SessionID},
				})
			}
		}
		if session.VLAN != "" || session.NASIP != "" {
			key := session.EndpointID + "|" + session.VLAN + "|" + session.NASIP
			if index, ok := accessIndex[key]; ok {
				item := &accessHistory[index]
				item.FirstSeen = shadowMin(item.FirstSeen, session.StartedAt)
				item.LastSeen = shadowMax(item.LastSeen, session.LastConfirmedAt)
			} else {
				accessIndex[key] = len(accessHistory)
				accessHistory = append(accessHistory, IdentityAccessHistory{
					EventID: session.SessionID, EndpointID: session.EndpointID, AccountID: session.AccountID,
					EntityRole: role, AccessType: "session", VLAN: session.VLAN, Source: session.Source,
					FirstSeen: session.StartedAt, LastSeen: session.LastConfirmedAt,
				})
			}
		}
	}
	return ipHistory, accessHistory
}
