package controlplane

import (
	"context"
	"sort"
	"time"

	"proxy-sentinel/internal/store"
)

type shadowSession struct {
	SessionID, AccountID, EndpointID, IP, MAC, Source, VLAN, NASIP, Status string
	StartedAt, EndedAt, LastConfirmedAt, UpdatedAt                         *time.Time
	Confidence                                                             float64
}

func (s *Server) shadowSessions(ctx context.Context, column, value string, limit int) ([]shadowSession, error) {
	if s.operations == nil || s.operations.db == nil || value == "" {
		return nil, nil
	}
	query := `SELECT session_id,account_id,endpoint_id,ip,mac,source,vlan,nas_ip,session_status,
started_at,ended_at,last_confirmed_at,updated_at,identity_confidence
FROM identity_session_shadow WHERE ` + column + `=$1 AND updated_at>now()-interval '24 hours'
ORDER BY updated_at DESC LIMIT $2`
	rows, err := s.operations.db.QueryContext(ctx, query, value, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []shadowSession{}
	for rows.Next() {
		var x shadowSession
		if err := rows.Scan(&x.SessionID, &x.AccountID, &x.EndpointID, &x.IP, &x.MAC, &x.Source, &x.VLAN, &x.NASIP, &x.Status,
			&x.StartedAt, &x.EndedAt, &x.LastConfirmedAt, &x.UpdatedAt, &x.Confidence); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Server) overlayAccountIdentity(ctx context.Context, profile *store.AccountIdentityProfile, accountID string) error {
	sessions, err := s.shadowSessions(ctx, "account_id", accountID, 200)
	if err != nil || len(sessions) == 0 {
		return err
	}
	byID := map[string]store.AccountSession{}
	for _, item := range profile.Sessions {
		byID[item.SessionID] = item
	}
	endpoints := map[string]store.EndpointEntity{}
	for _, item := range profile.Endpoints {
		endpoints[item.EndpointID] = item
	}
	latestSeen := profile.LastSeen
	for _, item := range sessions {
		converted := convertShadowSession(item)
		byID[converted.SessionID] = converted
		if item.EndpointID != "" {
			ep := endpoints[item.EndpointID]
			ep.EndpointID = item.EndpointID
			if ep.PrimaryMAC == "" {
				ep.PrimaryMAC = item.MAC
			}
			if ep.OwnerAccount == "" {
				ep.OwnerAccount = item.AccountID
			}
			if ep.LastSeen == "" {
				ep.LastSeen = convertShadowTime(item.LastConfirmedAt)
			}
			if ep.FirstSeen == "" {
				ep.FirstSeen = convertShadowTime(item.StartedAt)
			}
			endpoints[item.EndpointID] = ep
		}
		latestSeen = maxTimeString(latestSeen, convertShadowTime(item.LastConfirmedAt))
	}
	profile.Sessions = sortedSessions(byID)
	profile.Endpoints = profile.Endpoints[:0]
	for _, ep := range endpoints {
		profile.Endpoints = append(profile.Endpoints, ep)
	}
	sort.Slice(profile.Endpoints, func(i, j int) bool { return profile.Endpoints[i].LastSeen > profile.Endpoints[j].LastSeen })
	profile.LastSeen = latestSeen
	return nil
}

func (s *Server) overlayEndpointIdentity(ctx context.Context, profile *store.EndpointIdentityProfile, endpointID string) error {
	sessions, err := s.shadowSessions(ctx, "endpoint_id", endpointID, 200)
	if err != nil || len(sessions) == 0 {
		return err
	}
	byID := map[string]store.AccountSession{}
	for _, item := range profile.Sessions {
		byID[item.SessionID] = item
	}
	accounts := map[string]struct{}{}
	for _, item := range profile.Accounts {
		if item != "" {
			accounts[item] = struct{}{}
		}
	}
	for _, item := range sessions {
		converted := convertShadowSession(item)
		byID[converted.SessionID] = converted
		if item.AccountID != "" {
			accounts[item.AccountID] = struct{}{}
		}
	}
	profile.Sessions = sortedSessions(byID)
	profile.Accounts = profile.Accounts[:0]
	for id := range accounts {
		profile.Accounts = append(profile.Accounts, id)
	}
	sort.Strings(profile.Accounts)
	if len(sessions) > 0 {
		latest := sessions[0]
		if profile.Endpoint.PrimaryMAC == "" {
			profile.Endpoint.PrimaryMAC = latest.MAC
		}
		if profile.Endpoint.OwnerAccount == "" {
			profile.Endpoint.OwnerAccount = latest.AccountID
		}
		if latest.LastConfirmedAt != nil {
			profile.Endpoint.LastSeen = convertShadowTime(latest.LastConfirmedAt)
			profile.LastSeen = maxTimeString(profile.LastSeen, profile.Endpoint.LastSeen)
		}
	}
	return nil
}

func convertShadowSession(x shadowSession) store.AccountSession {
	return store.AccountSession{
		SessionID: x.SessionID, AccountID: x.AccountID, EndpointID: x.EndpointID,
		IP: x.IP, MAC: x.MAC, Source: x.Source, StartedAt: convertShadowTime(x.StartedAt),
		EndedAt: convertShadowTime(x.EndedAt), IdentityConfidence: x.Confidence,
		VLAN: x.VLAN, NASIP: x.NASIP, SessionStatus: x.Status,
		LastConfirmedAt: convertShadowTime(x.LastConfirmedAt),
	}
}

func convertShadowTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func maxTimeString(a, b string) string {
	if b > a {
		return b
	}
	return a
}

func sortedSessions(byID map[string]store.AccountSession) []store.AccountSession {
	out := make([]store.AccountSession, 0, len(byID))
	for _, item := range byID {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt == out[j].StartedAt {
			return out[i].SessionID > out[j].SessionID
		}
		return out[i].StartedAt > out[j].StartedAt
	})
	return out
}

type accountIdentityShadowReader interface {
	GetAccountIdentityShadow(context.Context, string, store.Query) (store.AccountIdentityProfile, bool, error)
}

type endpointIdentityShadowReader interface {
	GetEndpointIdentityShadow(context.Context, string, store.Query) (store.EndpointIdentityProfile, bool, error)
}
