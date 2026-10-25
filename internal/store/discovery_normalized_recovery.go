package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

// DiscoveryArchiveWriter uses durable scoped receipts, not ClickHouse's finite
// block window. Session locks serialize overlapping event sets without holding
// a PostgreSQL transaction during HTTP I/O. Ordinary ingest remains unchanged.
type DiscoveryArchiveWriter struct {
	db *sql.DB
	ch *ClickHouseStore
}

func NewDiscoveryArchiveWriter(db *sql.DB, ch *ClickHouseStore) *DiscoveryArchiveWriter {
	return &DiscoveryArchiveWriter{db, ch}
}

// ValidateRecovery checks the live migration and insertion mode before any
// task is claimed. The finite block window remains an optimization, not proof.
func (w *DiscoveryArchiveWriter) ValidateRecovery(ctx context.Context) error {
	rows, err := w.db.QueryContext(ctx, `SELECT content_hash,confirmed_at,last_query_id FROM discovery_normalized_receipts LIMIT 0`)
	if err != nil {
		return fmt.Errorf("discovery recovery schema unavailable: %w", err)
	}
	rows.Close()
	raw, err := w.ch.query(ctx, `SELECT extract(create_table_query,'non_replicated_deduplication_window = ([0-9]+)') dedup_window FROM system.tables WHERE database=currentDatabase() AND name='normalized_events' FORMAT JSONEachRow`)
	if err != nil {
		return err
	}
	var settings []struct {
		Window string `json:"dedup_window"`
	}
	if err = decodeJSONEachRow(raw, &settings); err != nil {
		return err
	}
	if len(settings) != 1 {
		return fmt.Errorf("normalized event table unavailable")
	}
	if eventIDScanDisabled() && (settings[0].Window == "" || settings[0].Window == "0") {
		return fmt.Errorf("ClickHouse insertion deduplication configuration mismatch")
	}
	return nil
}
func discoveryRevision(e normalized.Event) int64 {
	var n int64
	_, _ = fmt.Sscan(fmt.Sprint(e.Payload["revision"]), &n)
	return n
}
func discoverySource(e normalized.Event) string {
	if s := stringFromMap(e.Observer, "source_id"); s != "" {
		return s
	}
	return e.Source
}
func discoveryEventKey(e normalized.Event) string {
	b, _ := json.Marshal([]any{stringFromMap(e.Observer, "sensor_id"), discoverySource(e), e.EventID, discoveryRevision(e)})
	return string(b)
}
func discoveryRawHash(e normalized.Event) string {
	b, _ := json.Marshal(e)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func discoveryComparableEvent(e normalized.Event) (string, error) {
	at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		return "", err
	}
	e.Timestamp = at.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	// ClickHouse serializes absent maps as {}. Preserve all actual fields.
	if e.Subject == nil {
		e.Subject = map[string]any{}
	}
	if e.Flow == nil {
		e.Flow = map[string]any{}
	}
	return discoveryRawHash(e), nil
}

func (w *DiscoveryArchiveWriter) Write(ctx context.Context, input []normalized.Event) (resultErr error) {
	if len(input) == 0 {
		return nil
	}
	if len(input) > 50 {
		return fmt.Errorf("discovery segment exceeds 50 events")
	}
	events := make([]normalized.Event, 0, len(input))
	seen := map[string]string{}
	for _, e := range input {
		if e.EventID == "" || stringFromMap(e.Observer, "sensor_id") == "" {
			return fmt.Errorf("discovery event identity required")
		}
		k, h := discoveryEventKey(e), discoveryRawHash(e)
		if prior, ok := seen[k]; ok {
			if prior != h {
				return discovery.ErrDiscoveryContentConflict
			}
			continue
		}
		seen[k] = h
		events = append(events, e)
	}
	sort.Slice(events, func(i, j int) bool { return discoveryEventKey(events[i]) < discoveryEventKey(events[j]) })
	conn, err := w.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Never return a session with advisory locks to the pool, even on cancellation.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if _, e := conn.ExecContext(cleanup, "SELECT pg_advisory_unlock_all()"); e != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	started := time.Now()
	keys := make([]string, 0, len(events))
	for _, e := range events {
		keys = append(keys, discoveryEventKey(e))
	}
	rawKeys, _ := json.Marshal(keys)
	_, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended(k,9183992)) FROM (SELECT value k FROM jsonb_array_elements_text($1::jsonb) ORDER BY value) ordered`, rawKeys)
	discovery.ObserveStage(ctx, "normalized_locks", started, err)
	if err != nil {
		return err
	}
	// Existing projection receipts also prove that legacy archive completed.
	values, args := []string{}, []any{}
	for _, e := range events {
		n := len(args)
		values = append(values, fmt.Sprintf("($%d::text,$%d::text,$%d::text,$%d::bigint,$%d::text)", n+1, n+2, n+3, n+4, n+5))
		args = append(args, stringFromMap(e.Observer, "sensor_id"), discoverySource(e), e.EventID, discoveryRevision(e), discoveryRawHash(e))
	}
	wanted := "(VALUES " + strings.Join(values, ",") + ") AS v(sensor_id,source_id,event_id,revision,content_hash)"
	rows, err := conn.QueryContext(ctx, `SELECT r.sensor_id,r.source_id,r.event_id,r.revision,r.content_hash,r.batch_id FROM discovery_event_receipts r JOIN `+wanted+` USING(sensor_id,source_id,event_id,revision)`, args...)
	if err != nil {
		return err
	}
	applied := map[string]bool{}
	eventsByKey := map[string]normalized.Event{}
	for _, event := range events {
		eventsByKey[discoveryEventKey(event)] = event
	}
	type legacyReceipt struct{ key, hash, batch string }
	var legacy []legacyReceipt
	for rows.Next() {
		var sensor, source, id, hash, batch string
		var revision int64
		if err = rows.Scan(&sensor, &source, &id, &revision, &hash, &batch); err != nil {
			break
		}
		k, _ := json.Marshal([]any{sensor, source, id, revision})
		if hash != seen[string(k)] {
			legacy = append(legacy, legacyReceipt{string(k), hash, batch})
		}
		applied[string(k)] = true
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	originalBatches := map[string][]byte{}
	for _, receipt := range legacy {
		original, ok := originalBatches[receipt.batch]
		if !ok {
			if err = conn.QueryRowContext(ctx, `SELECT events FROM discovery_batch_work WHERE batch_id=$1`, receipt.batch).Scan(&original); err != nil {
				return fmt.Errorf("legacy receipt original evidence unavailable: %w", discovery.ErrDiscoveryContentConflict)
			}
			originalBatches[receipt.batch] = original
		}
		if !discovery.ReceiptMatchesEvent(eventsByKey[receipt.key], receipt.hash, original) {
			return discovery.ErrDiscoveryContentConflict
		}
	}
	if len(applied) == len(events) {
		return nil
	}
	// Retries are common after a partial archive. A matching conflict must not
	// rewrite fifty receipt rows just to rediscover their prior state. Advisory
	// locks above keep this insert and the following comparison serialized.
	admissionArgs := append(append([]any{}, args...), discovery.ArchiveAdmission(ctx))
	_, err = conn.ExecContext(ctx, `INSERT INTO discovery_normalized_receipts(sensor_id,source_id,event_id,revision,content_hash,first_attempt_at) SELECT v.*,$`+fmt.Sprint(len(admissionArgs))+`::timestamptz FROM `+wanted+` WHERE true
 ON CONFLICT(sensor_id,source_id,event_id,revision) DO NOTHING`, admissionArgs...)
	if err != nil {
		return err
	}
	rows, err = conn.QueryContext(ctx, `SELECT n.sensor_id,n.source_id,n.event_id,n.revision,n.content_hash,n.verified_at,n.resolve_after,n.last_query_id
 FROM discovery_normalized_receipts n JOIN `+wanted+` USING(sensor_id,source_id,event_id,revision)`, args...)
	if err != nil {
		return err
	}
	verified := map[string]bool{}
	resolve := map[string]time.Time{}
	queryIDs := map[string]bool{}
	count := 0
	for rows.Next() {
		var sensor, source, id, hash string
		var revision int64
		var at sql.NullTime
		var after time.Time
		var queryID string
		if err = rows.Scan(&sensor, &source, &id, &revision, &hash, &at, &after, &queryID); err != nil {
			break
		}
		k, _ := json.Marshal([]any{sensor, source, id, revision})
		if hash != seen[string(k)] {
			err = discovery.ErrDiscoveryContentConflict
			break
		}
		verified[string(k)] = at.Valid || applied[string(k)]
		resolve[string(k)] = after
		if queryID != "" {
			queryIDs[queryID] = true
		}
		count++
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if count != len(events) {
		return discovery.ErrDiscoveryContentConflict
	}
	if len(applied) > 0 {
		if _, err = conn.ExecContext(ctx, `UPDATE discovery_normalized_receipts n SET verified_at=coalesce(n.verified_at,r.applied_at),confirmed_at=coalesce(n.confirmed_at,r.standard_stored_at,r.accepted_at),confirmation_uncertain=CASE WHEN n.confirmed_at IS NULL THEN r.storage_time_uncertain ELSE n.confirmation_uncertain END FROM `+wanted+` JOIN discovery_event_receipts r USING(sensor_id,source_id,event_id,revision) WHERE (n.sensor_id,n.source_id,n.event_id,n.revision)=(v.sensor_id,v.source_id,v.event_id,v.revision) AND n.content_hash=v.content_hash`, args...); err != nil {
			return err
		}
	}
	pending := []normalized.Event{}
	for _, e := range events {
		if !verified[discoveryEventKey(e)] {
			pending = append(pending, e)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	// Check prior server-side requests before reading rows, not after: otherwise
	// an INSERT could finish between a negative lookup and the activity check.
	if len(queryIDs) > 0 {
		ids := []string{}
		for id := range queryIDs {
			ids = append(ids, chQuote(id))
		}
		raw, e := w.ch.query(ctx, "SELECT count() AS active FROM system.processes WHERE query_id IN ("+strings.Join(ids, ",")+") FORMAT JSONEachRow")
		if e != nil {
			return e
		}
		var rows []struct {
			Active int `json:"active"`
		}
		if e = decodeJSONEachRow(raw, &rows); e != nil {
			return e
		}
		if len(rows) != 1 {
			return fmt.Errorf("discovery query state unavailable")
		}
		if rows[0].Active > 0 {
			return fmt.Errorf("discovery normalized write still running")
		}
	}
	started = time.Now()
	found, err := w.ch.existingDiscoveryEvents(ctx, pending)
	discovery.ObserveStage(ctx, "normalized_reconcile", started, err)
	if err != nil {
		return err
	}
	missing := []normalized.Event{}
	for _, e := range pending {
		if !found[discoveryEventKey(e)] {
			if time.Now().Before(resolve[discoveryEventKey(e)]) {
				return fmt.Errorf("discovery normalized write outcome pending")
			}
			missing = append(missing, e)
		}
	}
	if len(missing) > 0 {
		body, _ := json.Marshal(missing)
		digest := sha256.Sum256(body)
		queryID := "discovery-normalized-" + hex.EncodeToString(digest[:])
		queryArgs := append(append([]any{}, args...), queryID)
		// A cancelled HTTP INSERT can finish server-side. A subsequent attempt first
		// reconciles the exact rows and waits out this uncertainty before any insert.
		if _, err = conn.ExecContext(ctx, `UPDATE discovery_normalized_receipts r SET resolve_after=now()+interval '30 seconds',last_query_id=$`+fmt.Sprint(len(queryArgs))+` FROM `+wanted+` WHERE (r.sensor_id,r.source_id,r.event_id,r.revision)=(v.sensor_id,v.source_id,v.event_id,v.revision) AND r.verified_at IS NULL`, queryArgs...); err != nil {
			return err
		}
		started = time.Now()
		parsed, e := url.Parse(w.ch.dsn)
		if e != nil {
			return e
		}
		params := parsed.Query()
		params.Set("query_id", queryID)
		params.Set("max_execution_time", "2")
		params.Set("max_threads", "1")
		parsed.RawQuery = params.Encode()
		bounded := *w.ch
		bounded.dsn = parsed.String()
		err = bounded.insertNormalizedEvents(ctx, missing)
		discovery.ObserveStage(ctx, "normalized_write", started, err)
		if err != nil {
			return err
		}
	}
	confirmationArgs := append(append([]any{}, args...), len(found) > 0)
	_, err = conn.ExecContext(ctx, `UPDATE discovery_normalized_receipts r SET verified_at=coalesce(r.verified_at,now()),confirmed_at=coalesce(r.confirmed_at,CASE WHEN $`+fmt.Sprint(len(confirmationArgs))+`::boolean THEN r.first_attempt_at ELSE now() END),confirmation_uncertain=CASE WHEN r.confirmed_at IS NULL THEN $`+fmt.Sprint(len(confirmationArgs))+`::boolean ELSE r.confirmation_uncertain END FROM `+wanted+` WHERE (r.sensor_id,r.source_id,r.event_id,r.revision)=(v.sensor_id,v.source_id,v.event_id,v.revision)`, confirmationArgs...)
	return err
}

func (s *ClickHouseStore) existingDiscoveryEvents(ctx context.Context, events []normalized.Event) (map[string]bool, error) {
	found := map[string]bool{}
	if len(events) == 0 {
		return found, nil
	}
	groups := map[string][]normalized.Event{}
	expected := map[string]string{}
	for _, e := range events {
		hash, err := discoveryComparableEvent(e)
		if err != nil {
			return nil, err
		}
		expected[discoveryEventKey(e)] = hash
		k, _ := json.Marshal([]string{stringFromMap(e.Observer, "sensor_id"), stringFromMap(e.Subject, "ip")})
		groups[string(k)] = append(groups[string(k)], e)
	}
	clauses := []string{}
	for _, group := range groups {
		ids := []string{}
		var from, to time.Time
		for _, e := range group {
			at, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
			at = at.UTC().Truncate(time.Microsecond)
			if from.IsZero() || at.Before(from) {
				from = at
			}
			if to.IsZero() || at.After(to) {
				to = at
			}
			ids = append(ids, chQuote(e.EventID))
		}
		clauses = append(clauses, `(sensor_id=`+chQuote(stringFromMap(group[0].Observer, "sensor_id"))+` AND subject_ip=`+chQuote(stringFromMap(group[0].Subject, "ip"))+` AND timestamp>=parseDateTime64BestEffort(`+chQuote(from.Format(time.RFC3339Nano))+`,6) AND timestamp<=parseDateTime64BestEffort(`+chQuote(to.Format(time.RFC3339Nano))+`,6) AND event_id IN (`+strings.Join(ids, ",")+`))`)
	}
	sort.Strings(clauses)
	q := `SELECT event_id,schema_version,source,source_event_type,type,formatDateTime(timestamp,'%Y-%m-%dT%H:%i:%S.%fZ','UTC') event_timestamp,observer_json,subject_json,payload_json,flow_json,raw_ref_json,confidence FROM normalized_events WHERE ` + strings.Join(clauses, " OR ") + ` LIMIT 1001 SETTINGS max_threads=1,max_execution_time=2 FORMAT JSONEachRow`
	raw, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		EventID    string  `json:"event_id"`
		Schema     string  `json:"schema_version"`
		Source     string  `json:"source"`
		SourceType string  `json:"source_event_type"`
		Type       string  `json:"type"`
		Timestamp  string  `json:"event_timestamp"`
		Observer   string  `json:"observer_json"`
		Subject    string  `json:"subject_json"`
		Payload    string  `json:"payload_json"`
		Flow       string  `json:"flow_json"`
		RawRef     string  `json:"raw_ref_json"`
		Confidence float64 `json:"confidence"`
	}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return nil, err
	}
	if len(rows) > 1000 {
		return nil, fmt.Errorf("discovery reconciliation row budget exceeded")
	}
	for _, row := range rows {
		e := normalized.Event{EventID: row.EventID, SchemaVersion: row.Schema, Source: row.Source, SourceEventType: row.SourceType, Type: row.Type, Timestamp: row.Timestamp, Confidence: row.Confidence}
		for _, item := range []struct {
			raw    string
			target *map[string]any
		}{{row.Observer, &e.Observer}, {row.Subject, &e.Subject}, {row.Payload, &e.Payload}, {row.Flow, &e.Flow}, {row.RawRef, &e.RawRef}} {
			if item.raw != "" {
				if err = json.Unmarshal([]byte(item.raw), item.target); err != nil {
					return nil, err
				}
			}
		}
		key := discoveryEventKey(e)
		want, ok := expected[key]
		if !ok {
			continue
		}
		hash, err := discoveryComparableEvent(e)
		if err != nil {
			return nil, err
		}
		if hash != want {
			return nil, discovery.ErrDiscoveryContentConflict
		}
		if found[key] {
			return nil, discovery.ErrDiscoveryContentConflict
		}
		found[key] = true
	}
	return found, nil
}
