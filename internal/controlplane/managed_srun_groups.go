package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	"proxy-sentinel/internal/srunapi"
)

const managedGroupReconcileInterval = 6 * time.Hour

type managedSRunGroupTarget struct {
	host    string
	version int64
}

func managedSRunGroupTargetFor(ctx context.Context, db *sql.DB, bridgeID string) (managedSRunGroupTarget, error) {
	var target managedSRunGroupTarget
	err := db.QueryRowContext(ctx, `SELECT active_host,active_config_version FROM identity_bridge_runtime WHERE bridge_id=$1 AND active_config_version>0 AND last_snapshot_at>now()-interval '30 seconds'`, bridgeID).Scan(&target.host, &target.version)
	if err != nil {
		return managedSRunGroupTarget{}, err
	}
	if !validSRunHost(target.host) || target.version < 1 {
		return managedSRunGroupTarget{}, errBridgeCatalogScope
	}
	return target, nil
}

func (s *Server) syncManagedSRunGroups(ctx context.Context, target managedSRunGroupTarget) (int, error) {
	if s.operations == nil || s.operations.db == nil {
		return 0, errors.New("group_directory_storage_unavailable")
	}
	var item srun4KIntegration
	if err := s.operations.db.QueryRowContext(ctx, `SELECT connector_id,host,authorization_database_host,online_redis_host,catalog_redis_host,event_redis_host,northbound_api_host FROM srun4k_integrations WHERE online_redis_host=$1 AND northbound_app_id<>'' AND octet_length(encrypted_northbound_app_secret)>0 ORDER BY updated_at DESC LIMIT 1`, target.host).Scan(&item.ConnectorID, &item.Host, &item.AuthorizationDatabaseHost, &item.OnlineRedisHost, &item.CatalogRedisHost, &item.EventRedisHost, &item.NorthboundAPIHost); err != nil {
		return 0, errors.New("managed_4k_integration_unavailable")
	}
	item.Source = s.identityBridge.normalized().Source
	client, err := s.srunClient(ctx, item)
	if err != nil {
		return 0, errors.New("authorization_database_unavailable")
	}
	defer client.CloseIdleConnections()
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	groups, err := client.Groups(ctx)
	if err != nil {
		return 0, managedGroupReadErrorType(err)
	}
	groupSource := managedGroupCatalogSource(item.Source, target.version)
	if err = s.commitSRunGroupsScoped(ctx, groupSource, groups, observedAt, target.host, target.version); err != nil {
		if errors.Is(err, errBridgeCatalogScope) {
			return 0, errBridgeCatalogScope
		}
		return 0, errors.New("group_directory_commit_failed")
	}
	return len(groups), nil
}

func managedGroupReadErrorType(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, srunapi.ErrAuthentication):
		return errors.New("northbound_authentication_failed")
	case errors.Is(err, srunapi.ErrReadOnlyQuery):
		return errors.New("northbound_group_query_failed")
	default:
		return errors.New("northbound_unavailable")
	}
}

func (s *Server) runManagedSRunGroupScheduler(ctx context.Context) {
	if s.operations == nil || s.operations.db == nil || s.readOnly && !s.allowIdentityIngest {
		return
	}
	var lastTarget managedSRunGroupTarget
	var lastSuccess time.Time
	nextAttempt := time.Time{}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(nextAttempt) {
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			target, err := managedSRunGroupTargetFor(probeCtx, s.operations.db, s.identityBridge.normalized().BridgeID)
			cancel()
			if err == nil {
				changed := target != lastTarget
				if changed || lastSuccess.IsZero() || now.Sub(lastSuccess) >= managedGroupReconcileInterval {
					syncCtx, syncCancel := context.WithTimeout(ctx, 45*time.Second)
					count, syncErr := s.syncManagedSRunGroups(syncCtx, target)
					syncCancel()
					if syncErr != nil {
						log.Printf("managed 4K group sync failed: source=%s version=%d category=%s", managedGroupCatalogSource(s.identityBridge.normalized().Source, target.version), target.version, syncErr.Error())
						nextAttempt = time.Now().Add(30 * time.Second)
					} else {
						lastTarget, lastSuccess, nextAttempt = target, time.Now(), time.Time{}
						log.Printf("managed 4K group sync completed: source=%s version=%d groups=%d", managedGroupCatalogSource(s.identityBridge.normalized().Source, target.version), target.version, count)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
