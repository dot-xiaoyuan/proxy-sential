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
