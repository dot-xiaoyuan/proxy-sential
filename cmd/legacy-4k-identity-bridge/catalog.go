package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"proxy-sentinel/internal/productpolicy"
)

var errCatalogHostChanged = errors.New("committed identity host changed during catalog read")

type catalogSyncer struct {
	cfg     config
	sender  productpolicy.Sender
	read    func(context.Context, string) (productpolicy.Snapshot, error)
	pending *productpolicy.BridgeCatalogSnapshot
}

func (s *catalogSyncer) syncOnce(ctx context.Context, state *runtimeState) error {
	state.mu.RLock()
	host, version, redisAddr := state.activeHost, state.activeConfigVersion, state.activeCatalogRedisAddr
	state.mu.RUnlock()
	if host == "" || version < 1 {
		return errCatalogHostChanged
	}
	if redisAddr == "" {
		redisAddr = net.JoinHostPort(host, strconv.Itoa(s.cfg.catalogPort))
	}
	if s.pending != nil && (s.pending.Host != host || s.pending.ConfigVersion != version) {
		s.pending = nil
	}
	if s.pending == nil {
		snapshot, err := s.read(ctx, redisAddr)
		if err != nil {
			return err
		}
		s.pending = &productpolicy.BridgeCatalogSnapshot{Host: host, ConfigVersion: version, Snapshot: snapshot}
	}
	state.mu.RLock()
	unchanged := state.activeHost == host && state.activeConfigVersion == version
	state.mu.RUnlock()
	if !unchanged {
		s.pending = nil
		return errCatalogHostChanged
	}
	if err := s.sender.SendBridgeCatalog(ctx, *s.pending, s.pending.ID()); err != nil {
		return err
	}
	state.mu.Lock()
	if state.activeHost == host && state.activeConfigVersion == version {
		state.catalogState = "healthy"
		state.lastCatalogAt = s.pending.Snapshot.ObservedAt
		state.catalogProducts = len(s.pending.Snapshot.Products)
		state.catalogControls = len(s.pending.Snapshot.Controls)
		state.catalogErrorType = ""
	}
	state.mu.Unlock()
	logStatus("catalog_committed", map[string]any{"source": s.cfg.source, "products": len(s.pending.Snapshot.Products), "controls": len(s.pending.Snapshot.Controls), "summary": s.pending.Snapshot.ContentHash})
	s.pending = nil
	return nil
}

// Independent from notification processing and online calibration. Product
// control rows are reference data only; this worker never creates actions.
func runCatalogWorker(ctx context.Context, cfg config, password, token string, state *runtimeState) {
	syncer := catalogSyncer{cfg: cfg, sender: productpolicy.Sender{Endpoint: cfg.endpoint, Token: token}, read: func(ctx context.Context, addr string) (productpolicy.Snapshot, error) {
		client := productpolicy.NewRedisCatalogClient(&redis.Options{Addr: addr, Password: password, DialTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 3 * time.Second, PoolSize: 2, MaxRetries: 1, ContextTimeoutEnabled: true})
		defer client.Close()
		return productpolicy.ReadRedisSnapshot(ctx, client, cfg.source, 10000)
	}}
	next := time.Time{}
	version := int64(0)
	for ctx.Err() == nil {
		state.mu.RLock()
		activeVersion := state.activeConfigVersion
		state.mu.RUnlock()
		if activeVersion > 0 && (activeVersion != version || !time.Now().Before(next)) {
			version = activeVersion
			callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			err := syncer.syncOnce(callCtx, state)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				state.mu.Lock()
				state.catalogState, state.catalogErrorType = "failed", errorType(err)
				state.mu.Unlock()
				logStatus("catalog_failed", map[string]any{"error_type": errorType(err)})
				next = time.Now().Add(30 * time.Second)
			} else {
				next = time.Now().Add(cfg.catalogInterval)
			}
		}
		if !waitContext(ctx, time.Second) {
			return
		}
	}
}
