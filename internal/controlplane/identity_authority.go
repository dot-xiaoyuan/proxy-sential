package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
	"strings"
)

var errIdentityAuthorityUnavailable = errors.New("身份来源配置查询失败")
var errIdentityAuthorityUnregistered = errors.New("identity source is not registered for this sensor, campus and access domain")

// Callers may expose Error in an API response. Preserve the internal cause
// for errors.Is/As without exposing database addresses or driver details.
type identityAuthorityUnavailableError struct{ cause error }

func (e identityAuthorityUnavailableError) Error() string {
	return errIdentityAuthorityUnavailable.Error()
}
func (e identityAuthorityUnavailableError) Unwrap() []error {
	return []error{errIdentityAuthorityUnavailable, e.cause}
}

type identityAuthorityResult struct {
	interval   int
	registered bool
}

// One batch observes each exact authority once. Never retain this resolver
// between requests: source removal and changed intervals must take effect.
type identityAuthorityResolver struct {
	server   *Server
	resolved map[store.IdentityScope]identityAuthorityResult
}

func newIdentityAuthorityResolver(s *Server) *identityAuthorityResolver {
	return &identityAuthorityResolver{server: s, resolved: map[store.IdentityScope]identityAuthorityResult{}}
}
func (a *identityAuthorityResolver) resolve(ctx context.Context, scope store.IdentityScope) (identityAuthorityResult, error) {
	if err := ctx.Err(); err != nil {
		return identityAuthorityResult{}, err
	}
	if result, ok := a.resolved[scope]; ok {
		return result, nil
	}
	for _, source := range a.server.identitySources {
		if source.IdentityScope == scope {
			if err := ctx.Err(); err != nil {
				return identityAuthorityResult{}, err
			}
			result := identityAuthorityResult{interval: source.IntervalSeconds, registered: true}
			a.resolved[scope] = result
			return result, nil
		}
	}
	interval, registered, err := a.server.srunIdentityRegistrationContext(ctx, scope)
	if err != nil {
		return identityAuthorityResult{}, err
	}
	result := identityAuthorityResult{interval: interval, registered: registered}
	a.resolved[scope] = result
	return result, nil
}

func (s *Server) srunIdentityRegistrationContext(ctx context.Context, scope store.IdentityScope) (int, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	// Native 4K observations declare no campus/access domain. Extra scopes
	// require an explicit static registration rather than borrowing this one.
	if scope.CampusID != "" || scope.AccessDomain != "" || s.operations == nil || s.operations.db == nil || !strings.HasPrefix(scope.Source, "srun4k:") {
		return 0, false, nil
	}
	var interval int
	err := s.operations.db.QueryRowContext(ctx, `SELECT reconcile_interval_hours*3600 FROM srun4k_integrations WHERE source=$1 AND sensor_id=$2`, scope.Source, scope.SensorID).Scan(&interval)
	if interrupted := ctx.Err(); interrupted != nil {
		return 0, false, interrupted
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, identityAuthorityUnavailableError{cause: err}
	}
	return interval, true, nil
}

func (s *Server) validateIdentitySourceContext(ctx context.Context, scope store.IdentityScope, interval int) error {
	result, err := newIdentityAuthorityResolver(s).resolve(ctx, scope)
	if err != nil {
		return err
	}
	if !result.registered {
		return errIdentityAuthorityUnregistered
	}
	if result.interval != interval {
		return fmt.Errorf("identity interval differs from registered source")
	}
	return nil
}

func (s *Server) applyIdentityRegistrationContext(ctx context.Context, event *normalized.Event) error {
	return newIdentityAuthorityResolver(s).apply(ctx, event)
}

func (a *identityAuthorityResolver) apply(ctx context.Context, event *normalized.Event) error {
	sensor, _ := event.Observer["sensor_id"].(string)
	campus, _ := event.Subject["campus_id"].(string)
	domain, _ := event.Payload["access_domain"].(string)
	result, err := a.resolve(ctx, store.IdentityScope{Source: event.Source, SensorID: sensor, CampusID: campus, AccessDomain: domain})
	if err != nil {
		return err
	}
	if !result.registered {
		return errIdentityAuthorityUnregistered
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}
	event.Payload["heartbeat_interval_seconds"] = result.interval
	event.Payload["reconcile_interval_seconds"] = result.interval
	return nil
}

func writeIdentityAuthorityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, context.Canceled):
		writeError(w, http.StatusRequestTimeout, "identity_source_cancelled", "身份来源校验已取消，请重试")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, "identity_source_timeout", "身份来源校验超时，请重试")
	case errors.Is(err, errIdentityAuthorityUnavailable):
		writeError(w, http.StatusServiceUnavailable, "identity_source_unavailable", "身份来源配置暂不可用，请重试")
	default:
		writeError(w, http.StatusForbidden, "identity_source_not_registered", err.Error())
	}
}
