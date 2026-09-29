package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"sort"
	"strings"
	"time"
)

type identitySourceRegistration struct {
	store.IdentityScope
	IntervalSeconds int `json:"reconcile_interval_seconds"`
}

// Apply the current authority configuration at every policy read, including
// execution prechecks. Historical self-declared freshness cannot grant trust.
func (s *Server) policySessions(ctx context.Context, reader store.PolicyIdentityReader, at time.Time) ([]policy.Session, error) {
	return s.policySessionsForScope(ctx, reader, at, "", "")
}

func (s *Server) policySessionsForScope(ctx context.Context, reader store.PolicyIdentityReader, at time.Time, campus, domain string) ([]policy.Session, error) {
	var observed []policy.Session
	var err error
	if campus != "" && domain != "" {
		if scoped, ok := reader.(store.ScopedPolicyIdentityReader); ok {
			observed, err = scoped.ListPolicySessionsForScope(ctx, at, campus, domain)
		}
	}
	if observed == nil && err == nil {
		observed, err = reader.ListPolicySessions(ctx, at)
	}
	if err != nil {
		return nil, err
	}
	if campus != "" || domain != "" {
		scoped := observed[:0]
		for _, session := range observed {
			if (campus == "" || session.CampusID == campus) && (domain == "" || session.AccessDomain == domain) {
				scoped = append(scoped, session)
			}
		}
		observed = scoped
	}
	var managed []managedIdentityRegistration
	if campus != "" && domain != "" {
		managed, err = s.managedIdentityRegistrationsByScope(ctx, campus, domain)
	} else {
		managed, err = s.managedIdentityRegistrations(ctx)
	}
	if err != nil {
		return nil, err
	}
	out := append([]policy.Session{}, observed...)
	for i := range out {
		out[i].IdentityIssue = "unregistered_source"
		scope := store.IdentityScope{Source: out[i].Source, SensorID: out[i].SensorID, CampusID: out[i].CampusID, AccessDomain: out[i].AccessDomain}
		for _, source := range s.identitySources {
			if source.IdentityScope == scope {
				out[i].IdentityIssue = ""
				out[i].HeartbeatSeconds = source.IntervalSeconds
				out[i].ReconcileSeconds = source.IntervalSeconds
				break
			}
		}

		for _, source := range managed {
			if source.Config.IdentityScope == scope {
				out[i].IdentityIssue = "identity_source_unavailable"
				if source.Config.Enabled && source.State == "healthy" && source.ObservedAt.Valid && !source.ObservedAt.Time.After(at) && at.Sub(source.ObservedAt.Time) <= 5*time.Second {
					out[i].IdentityIssue = ""
					out[i].HeartbeatSeconds = 5
					out[i].ReconcileSeconds = 5
				}
				break
			}
		}
	}
	return out, nil
}

func loadIdentitySources(path string) ([]identitySourceRegistration, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("identity sources config exceeds 1MiB")
	}
	var cfg struct {
		Version string                       `json:"schema_version"`
		Sources []identitySourceRegistration `json:"sources"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&cfg); err != nil {
		return nil, err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("exactly one identity sources document required")
	}
	if cfg.Version != "identity-sources/v1" {
		return nil, fmt.Errorf("unsupported identity sources schema")
	}
	seen := map[store.IdentityScope]bool{}
	for _, source := range cfg.Sources {
		for _, value := range []string{source.Source, source.SensorID, source.CampusID, source.AccessDomain} {
			if value == "" || strings.TrimSpace(value) != value || len(value) > 200 {
				return nil, fmt.Errorf("identity source requires explicit scope")
			}
		}
		if seen[source.IdentityScope] || source.IntervalSeconds < 1 || source.IntervalSeconds > 86400 {
			return nil, fmt.Errorf("duplicate source or invalid reconciliation interval")
		}
		seen[source.IdentityScope] = true
	}
	return cfg.Sources, nil
}
func (s *Server) validateIdentitySource(scope store.IdentityScope, interval int) error {
	for _, source := range s.identitySources {
		if source.IdentityScope == scope {
			if interval != source.IntervalSeconds {
				return fmt.Errorf("identity interval differs from registered source")
			}
			return nil
		}
	}
	return fmt.Errorf("identity source is not registered for this sensor, campus and access domain")
}
func (s *Server) mergeIdentitySources(observed []store.IdentitySourceStatus, at time.Time) []store.IdentitySourceStatus {
	out := append([]store.IdentitySourceStatus{}, observed...)
	for _, registered := range s.identitySources {
		found := false
		for i := range out {
			if out[i].IdentityScope == registered.IdentityScope {
				found = true
				out[i].IntervalSeconds = registered.IntervalSeconds
				out[i].State = "healthy"
				if out[i].ObservedAt.IsZero() {
					out[i].State = "never_seen"
				} else if !at.Before(out[i].ObservedAt.Add(time.Duration(3*registered.IntervalSeconds) * time.Second)) {
					out[i].State = "interrupted"
				}
			}
		}
		if !found {
			out = append(out, store.IdentitySourceStatus{IdentityScope: registered.IdentityScope, IntervalSeconds: registered.IntervalSeconds, State: "never_seen"})
		}
	}
	for i := range out {
		registered := false
		for _, source := range s.identitySources {
			if source.IdentityScope == out[i].IdentityScope {
				registered = true
				break
			}
		}
		if !registered {
			out[i].State = "unregistered"
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i].IdentityScope)
		b, _ := json.Marshal(out[j].IdentityScope)
		return string(a) < string(b)
	})
	return out
}

// Freshness is controlled by registered collection configuration, not a sender's
// self-declared interval. Scope must be explicit on every normalized record.
func (s *Server) applyIdentityRegistration(event *normalized.Event) error {
	sensor, _ := event.Observer["sensor_id"].(string)
	campus, _ := event.Subject["campus_id"].(string)
	domain, _ := event.Payload["access_domain"].(string)
	scope := store.IdentityScope{Source: event.Source, SensorID: sensor, CampusID: campus, AccessDomain: domain}
	for _, source := range s.identitySources {
		if source.IdentityScope == scope {
			event.Payload["heartbeat_interval_seconds"] = source.IntervalSeconds
			event.Payload["reconcile_interval_seconds"] = source.IntervalSeconds
			return nil
		}
	}
	return fmt.Errorf("identity record has an unregistered source scope")
}

func (s *Server) mergeManagedIdentitySources(ctx context.Context, observed []store.IdentitySourceStatus, at time.Time) ([]store.IdentitySourceStatus, error) {
	out := s.mergeIdentitySources(observed, at)
	registrations, err := s.managedIdentityRegistrations(ctx)
	if err != nil {
		return nil, err
	}
	for _, registered := range registrations {
		index := -1
		for i := range out {
			if out[i].IdentityScope == registered.Config.IdentityScope {
				index = i
				break
			}
		}
		if index < 0 {
			out = append(out, store.IdentitySourceStatus{IdentityScope: registered.Config.IdentityScope})
			index = len(out) - 1
		}
		out[index].IntervalSeconds = 5
		out[index].State = registered.State
		out[index].Blocker = registered.Blocker
		if !registered.Config.Enabled {
			out[index].State = "disabled"
			out[index].Blocker = "identity_source_disabled"
		}
		if registered.ObservedAt.Valid {
			out[index].ObservedAt = registered.ObservedAt.Time
			out[index].AgeSeconds = at.Sub(registered.ObservedAt.Time).Seconds()
		}
		if out[index].State == "healthy" && (!registered.ObservedAt.Valid || registered.ObservedAt.Time.After(at) || at.Sub(registered.ObservedAt.Time) > 5*time.Second) {
			out[index].State = "stale"
			out[index].Blocker = "identity_source_stale"
		}
		out[index].SessionCount = registered.RecordCount
	}
	return out, nil
}
