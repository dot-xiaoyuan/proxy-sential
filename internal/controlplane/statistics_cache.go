package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type statisticsResponse struct {
	body        []byte
	contentType string
	asOf        time.Time
	status      int
}
type statisticsEntry struct {
	value   statisticsResponse
	loading chan struct{}
	touched time.Time
}
type statisticsCache struct {
	mu      sync.Mutex
	entries map[string]*statisticsEntry
}

// Statistics are produced by asynchronous ClickHouse read models. A five
// second hard failure budget made the overview unavailable whenever a normal
// rebuild briefly contended with ingest. Keep the response usable while a
// single-flight refresh catches up.
const (
	statisticsLoadLimit = 12 * time.Second
)

func newStatisticsCache() *statisticsCache {
	return &statisticsCache{entries: map[string]*statisticsEntry{}}
}
func isStatisticsRoute(path string) bool {
	switch path {
	case "/overview", "/activity/overview", "/activity/reports", "/dpi/overview", "/dpi/trends", "/dpi/protocol-flows", "/dpi/fingerprint-conflicts", "/device-fingerprint-conflicts", "/device-recognition/summary", "/application-activity":
		return true
	}
	return false
}
func statisticsKey(r *http.Request, path string) string {
	session := sessionFromContext(r.Context())
	permissions := append([]string{}, session.Permissions...)
	sort.Strings(permissions)
	// Authentication and current permission checks run before this cache. These
	// statistics are not actor-specific; network/account filters are in the URL.
	return session.User.ID + ":" + session.Role + ":" + strings.Join(permissions, ",") + ":" + path + "?" + r.URL.Query().Encode()
}

type statisticsWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *statisticsWriter) Header() http.Header { return w.header }
func (w *statisticsWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *statisticsWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(p)
}
func statisticsWrite(w http.ResponseWriter, value statisticsResponse) {
	value = statisticsFreshnessResponse(value)
	w.Header().Set("Content-Type", value.contentType)
	w.Header().Set("Cache-Control", "private, no-store")
	if value.status == 200 && !value.asOf.IsZero() {
		w.Header().Set("X-Statistics-As-Of", value.asOf.UTC().Format(time.RFC3339Nano))
	}
	w.WriteHeader(value.status)
	_, _ = w.Write(value.body)
}

func statisticsFreshnessResponse(value statisticsResponse) statisticsResponse {
	if value.status != http.StatusOK || value.asOf.IsZero() {
		return value
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(value.body, &body) != nil || body == nil {
		return value
	}
	lag := int64(time.Since(value.asOf).Seconds())
	if lag < 0 {
		lag = 0
	}
	status := "fresh"
	if lag > 300 {
		status = "stale"
	} else if lag > 60 {
		status = "delayed"
	}
	freshness := map[string]any{"status": status, "as_of": value.asOf.UTC().Format(time.RFC3339Nano), "lag_seconds": lag, "partial": false}
	if raw := body["data_freshness"]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &freshness)
		freshness["status"] = status
		freshness["as_of"] = value.asOf.UTC().Format(time.RFC3339Nano)
		freshness["lag_seconds"] = lag
	}
	body["data_freshness"], _ = json.Marshal(freshness)
	value.body, _ = json.Marshal(body)
	return value
}
func (c *statisticsCache) load(r *http.Request, path string, dispatch func(http.ResponseWriter, *http.Request, string)) (result statisticsResponse) {
	defer func() {
		if recover() != nil {
			result = statisticsResponse{body: []byte(`{"error":{"code":"statistics_refresh_failed","message":"statistics refresh failed"}}`), contentType: "application/json", status: 503}
		}
	}()
	started := time.Now()
	// A departing first browser must not cancel a shared statistics fill for
	// other authorized readers. The independent fill remains bounded.
	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), statisticsLoadLimit)
	defer cancel()
	r = r.Clone(loadCtx)
	buffer := &statisticsWriter{header: http.Header{}}
	dispatch(buffer, r, path)
	if buffer.status == 0 {
		buffer.status = 200
	}
	result = statisticsResponse{body: append([]byte(nil), buffer.body.Bytes()...), contentType: buffer.header.Get("Content-Type"), status: buffer.status, asOf: started}
	if result.status != 200 {
		return result
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(result.body, &body) == nil && body != nil {
		for _, field := range []string{"as_of", "statistics_as_of"} {
			var stamp string
			if json.Unmarshal(body[field], &stamp) == nil {
				if parsed, err := time.Parse(time.RFC3339Nano, stamp); err == nil && parsed.Before(result.asOf) {
					result.asOf = parsed
				}
			}
		}

		body["statistics_as_of"], _ = json.Marshal(result.asOf.UTC().Format(time.RFC3339Nano))
		result.body, _ = json.Marshal(body)
	}
	return result
}
func (c *statisticsCache) serve(w http.ResponseWriter, r *http.Request, path string, dispatch func(http.ResponseWriter, *http.Request, string)) {
	key := statisticsKey(r, path)
	for {
		c.mu.Lock()
		entry := c.entries[key]
		if entry == nil {
			if len(c.entries) >= 256 {
				var oldestKey string
				var oldest time.Time
				for k, v := range c.entries {
					if v.loading == nil && (oldest.IsZero() || v.touched.Before(oldest)) {
						oldestKey, oldest = k, v.touched
					}
				}
				if oldestKey != "" {
					delete(c.entries, oldestKey)
				}
			}
			// Never grow an unbounded filter/permission cache when all entries load.
			if len(c.entries) >= 256 {
				c.mu.Unlock()
				value := c.load(r, path, dispatch)
				statisticsWrite(w, value)
				return
			}
			entry = &statisticsEntry{}
			c.entries[key] = entry
		}
		entry.touched = time.Now()
		age := time.Since(entry.value.asOf)
		// Coalesce failed refreshes too. Otherwise every waiting reader becomes
		// the next expensive retry and a 20-client failure turns into a long queue.
		if entry.value.status >= 500 && age < time.Second {
			value := entry.value
			c.mu.Unlock()
			statisticsWrite(w, value)
			return
		}
		if entry.value.status == 200 {
			value := entry.value
			if age >= 2*time.Second && entry.loading == nil {
				entry.loading = make(chan struct{})
				// Refresh with the same validated permission/filter scope, independent of
				// a browser abort. Single-flight keeps 20 clients from repeating scans.
				go func(e *statisticsEntry) {
					ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), statisticsLoadLimit)
					defer cancel()
					value := c.load(r.WithContext(ctx), path, dispatch)
					c.mu.Lock()
					if value.status == 200 {
						e.value = value
					}
					close(e.loading)
					e.loading = nil
					c.mu.Unlock()
				}(entry)
			}
			c.mu.Unlock()
			statisticsWrite(w, value)
			return
		}
		if entry.loading != nil {
			done := entry.loading
			c.mu.Unlock()
			select {
			case <-done:
				continue
			case <-r.Context().Done():
				writeError(w, 503, "statistics_cancelled", "statistics request cancelled")
				return
			}
		}
		entry.loading = make(chan struct{})
		c.mu.Unlock()
		value := c.load(r, path, dispatch)
		c.mu.Lock()
		if value.status == 200 {
			entry.value = value
		} else if value.status >= 500 {
			if entry.value.status != 200 {
				value.asOf = time.Now()
				entry.value = value
			}
		}
		close(entry.loading)
		entry.loading = nil
		c.mu.Unlock()
		if value.status >= 500 && entry.value.status == 200 {
			value = entry.value
		}
		statisticsWrite(w, value)
		return
	}
}
