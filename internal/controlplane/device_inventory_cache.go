package controlplane

import (
	"context"
	"sync"
	"time"

	"proxy-sentinel/internal/store"
)

type deviceInventoryCacheEntry struct {
	page      store.DeviceInventoryListPage
	expiresAt time.Time
}

type deviceInventoryFlight struct {
	done chan struct{}
	page store.DeviceInventoryListPage
	err  error
}

// deviceInventoryPageCache coalesces identical list reads and keeps the
// prepared projection briefly warm. The short lifetime bounds staleness while
// preventing a burst of clients from repeating every facet/count/page query.
type deviceInventoryPageCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]deviceInventoryCacheEntry
	flights map[string]*deviceInventoryFlight
}

func newDeviceInventoryPageCache(ttl time.Duration) *deviceInventoryPageCache {
	return &deviceInventoryPageCache{
		ttl: ttl, entries: map[string]deviceInventoryCacheEntry{}, flights: map[string]*deviceInventoryFlight{},
	}
}

func (c *deviceInventoryPageCache) get(ctx context.Context, key string, load func(context.Context) (store.DeviceInventoryListPage, error)) (store.DeviceInventoryListPage, error) {
	return c.getMode(ctx, key, false, load)
}

func (c *deviceInventoryPageCache) getMode(ctx context.Context, key string, refresh bool, load func(context.Context) (store.DeviceInventoryListPage, error)) (store.DeviceInventoryListPage, error) {
	now := time.Now()
	c.mu.Lock()
	if refresh {
		delete(c.entries, key)
	}
	if entry, ok := c.entries[key]; ok && now.Before(entry.expiresAt) {
		c.mu.Unlock()
		return cloneDeviceInventoryPage(entry.page), nil
	}
	if flight := c.flights[key]; flight != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return store.DeviceInventoryListPage{}, ctx.Err()
		case <-flight.done:
			return cloneDeviceInventoryPage(flight.page), flight.err
		}
	}
	flight := &deviceInventoryFlight{done: make(chan struct{})}
	c.flights[key] = flight
	c.mu.Unlock()

	page, err := load(ctx)
	c.mu.Lock()
	flight.page, flight.err = page, err
	if err == nil {
		c.entries[key] = deviceInventoryCacheEntry{page: page, expiresAt: time.Now().Add(c.ttl)}
	}
	delete(c.flights, key)
	close(flight.done)
	if len(c.entries) > 128 {
		for cacheKey, entry := range c.entries {
			if time.Now().After(entry.expiresAt) {
				delete(c.entries, cacheKey)
			}
		}
		for len(c.entries) > 128 {
			var oldestKey string
			var oldest time.Time
			for k, entry := range c.entries {
				if oldest.IsZero() || entry.expiresAt.Before(oldest) {
					oldestKey, oldest = k, entry.expiresAt
				}
			}
			delete(c.entries, oldestKey)
		}
	}
	c.mu.Unlock()
	return cloneDeviceInventoryPage(page), err
}

func cloneDeviceInventoryPage(page store.DeviceInventoryListPage) store.DeviceInventoryListPage {
	page.Items = append([]store.DeviceInventoryListItem{}, page.Items...)
	page.Facets.Brands = append([]string{}, page.Facets.Brands...)
	page.Facets.OSFamilies = append([]string{}, page.Facets.OSFamilies...)
	return page
}
