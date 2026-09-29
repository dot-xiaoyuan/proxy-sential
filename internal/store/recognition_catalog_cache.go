package store

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

type recognitionCatalogEntry struct {
	items    []EndpointDeviceInventory
	asOf     time.Time
	loading  chan struct{}
	err      error
	failedAt time.Time
}
type recognitionCatalogCache struct {
	mu      sync.Mutex
	entries map[string]*recognitionCatalogEntry
}

const (
	recognitionCatalogFreshness    = 30 * time.Second
	recognitionCatalogRefreshAfter = 15 * time.Second
	recognitionCatalogLoadLimit    = 8 * time.Second
	recognitionCatalogRetryDelay   = 5 * time.Second
	recognitionCatalogStaleLimit   = 5 * time.Minute
)

// Facets and coverage are statistics; all row reads and synchronous registration
// writes still query the database. Same-scope readers share this metadata and use
// stale-while-revalidate so a transient refresh timeout cannot fail device pages.
func (s *PostgresStore) endpointRecognitionCatalog(ctx context.Context) ([]EndpointDeviceInventory, time.Time, error) {
	snapshot := ctx.Value(domainReadKey{}).(domainReadSnapshot)
	key := snapshot.version + ":" + strconv.FormatBool(snapshot.enabled) + ":" + fingerprint.Default().Version()
	cache := &s.recognitionCatalog
	for {
		cache.mu.Lock()
		if cache.entries == nil {
			cache.entries = map[string]*recognitionCatalogEntry{}
		}
		e := cache.entries[key]
		if e == nil {
			if len(cache.entries) >= 4 {
				for k, v := range cache.entries {
					if v.loading == nil {
						delete(cache.entries, k)
						break
					}
				}
			}
			if len(cache.entries) >= 4 {
				cache.mu.Unlock()
				items, err := s.loadEndpointRecognitionCatalog(ctx)
				return items, snapshot.now, err
			}
			e = &recognitionCatalogEntry{}
			cache.entries[key] = e
		}
		age := time.Since(e.asOf)
		if e.items != nil && (e.err == nil || age < recognitionCatalogStaleLimit) {
			items, asOf := e.items, e.asOf
			refreshDue := age >= recognitionCatalogRefreshAfter
			retryDue := e.err == nil || time.Since(e.failedAt) >= recognitionCatalogRetryDelay
			if refreshDue && retryDue && e.loading == nil {
				e.loading = make(chan struct{})
				go s.fillRecognitionCatalog(ctx, snapshot, e)
			}
			cache.mu.Unlock()
			return items, asOf, nil
		}
		if e.err != nil && time.Since(e.failedAt) < recognitionCatalogRetryDelay {
			err := e.err
			cache.mu.Unlock()
			return nil, time.Time{}, err
		}
		if e.loading != nil {
			done := e.loading
			cache.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, time.Time{}, ctx.Err()
			}
		}
		e.loading = make(chan struct{})
		cache.mu.Unlock()
		return s.fillRecognitionCatalog(ctx, snapshot, e)
	}
}

func (s *PostgresStore) fillRecognitionCatalog(ctx context.Context, snapshot domainReadSnapshot, e *recognitionCatalogEntry) (items []EndpointDeviceInventory, asOf time.Time, err error) {
	cache := &s.recognitionCatalog
	started := time.Now()
	fingerprintVersion := fingerprint.Default().Version()
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("recognition statistics refresh failed")
		}
		cache.mu.Lock()
		if err == nil {
			e.items = items
			e.asOf = started
			e.err = nil
		} else {
			e.err = err
			e.failedAt = time.Now()
		}
		close(e.loading)
		e.loading = nil
		cache.mu.Unlock()
	}()
	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recognitionCatalogLoadLimit)
	defer cancel()
	snapshot.now = started.UTC()
	loadCtx = context.WithValue(loadCtx, domainReadKey{}, snapshot)
	items, err = s.loadEndpointRecognitionCatalog(loadCtx)
	if err == nil && time.Since(started) >= recognitionCatalogFreshness {
		err = fmt.Errorf("recognition statistics exceeded the freshness budget")
	}
	if err == nil && fingerprint.Default().Version() != fingerprintVersion {
		err = fmt.Errorf("fingerprint version changed during statistics refresh")
	}
	return items, started, err
}

func (s *PostgresStore) WarmEndpointRecognitionCatalog(ctx context.Context) error {
	snapshotCtx, err := s.domainSnapshot(ctx)
	if err != nil {
		return err
	}
	_, _, err = s.endpointRecognitionCatalog(snapshotCtx)
	return err
}

func (s *PostgresStore) recognitionCatalogHealth(ctx context.Context) error {
	snapshotCtx, err := s.domainSnapshot(ctx)
	if err != nil {
		return err
	}
	snapshot := snapshotCtx.Value(domainReadKey{}).(domainReadSnapshot)
	key := snapshot.version + ":" + strconv.FormatBool(snapshot.enabled) + ":" + fingerprint.Default().Version()
	cache := &s.recognitionCatalog
	cache.mu.Lock()
	defer cache.mu.Unlock()
	e := cache.entries[key]
	if e == nil || e.items == nil {
		return fmt.Errorf("recognition statistics are not prepared")
	}
	if e.err != nil && time.Since(e.asOf) >= recognitionCatalogStaleLimit {
		return e.err
	}
	return nil
}
