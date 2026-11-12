package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"

	"proxy-sentinel/internal/census"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

type censusIdentifierSpan struct {
	census.Identifier
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	BucketAt  time.Time `json:"bucket_at,omitempty"`
}

type censusTaskPayload struct {
	Current  []censusIdentifierSpan `json:"current"`
	Buckets  []censusIdentifierSpan `json:"buckets"`
	Bindings []census.Binding       `json:"bindings"`
}

func coalesceCensusIdentifiers(events []normalized.Event, allow []string) ([]censusIdentifierSpan, []censusIdentifierSpan, []census.Binding, error) {
	if len(events) == 0 {
		return nil, nil, nil, nil
	}
	var prefixes []netip.Prefix
	for _, value := range allow {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 {
			return nil, nil, nil, fmt.Errorf("invalid census CIDR %q", value)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	current := map[string]censusIdentifierSpan{}
	buckets := map[string]censusIdentifierSpan{}
	bindings := map[string]census.Binding{}
	merge := func(target map[string]censusIdentifierSpan, key string, item censusIdentifierSpan) {
		prior, exists := target[key]
		if !exists {
			target[key] = item
			return
		}
		if item.FirstSeen.Before(prior.FirstSeen) {
			prior.FirstSeen = item.FirstSeen
		}
		if item.LastSeen.After(prior.LastSeen) || item.LastSeen.Equal(prior.LastSeen) && item.EventID > prior.EventID {
			prior.LastSeen, prior.EventID, prior.Source = item.LastSeen, item.EventID, item.Source
		}
		target[key] = prior
	}
	for _, event := range events {
		ids, pairs := census.Identify(event, prefixes)
		for _, id := range ids {
			item := censusIdentifierSpan{Identifier: id, FirstSeen: id.ObservedAt, LastSeen: id.ObservedAt}
			key := id.ScopeKey + "\x00" + id.Kind + "\x00" + id.Value
			merge(current, key, item)
			item.BucketAt = id.ObservedAt.Truncate(5 * time.Minute)
			merge(buckets, item.BucketAt.Format(time.RFC3339)+"\x00"+key, item)
		}
		for _, pair := range pairs {
			key := pair.ScopeKey + "\x00" + pair.IP + "\x00" + pair.MAC
			prior, exists := bindings[key]
			if !exists || pair.ObservedAt.After(prior.ObservedAt) || pair.ObservedAt.Equal(prior.ObservedAt) && pair.Withdrawn && !prior.Withdrawn {
				bindings[key] = pair
			}
		}
	}
	toSpans := func(source map[string]censusIdentifierSpan) []censusIdentifierSpan {
		keys := make([]string, 0, len(source))
		for key := range source {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		result := make([]censusIdentifierSpan, 0, len(keys))
		for _, key := range keys {
			result = append(result, source[key])
		}
		return result
	}
	pairKeys := make([]string, 0, len(bindings))
	// A later authoritative DHCP ACK replaces an older claim for the same
	// scoped IP. ARP/NDP disagreement remains visible as a conflict.
	for key, incoming := range bindings {
		if len(incoming.Source) < 5 || incoming.Source[:5] != "dhcp:" || incoming.Withdrawn {
			continue
		}
		for oldKey, old := range bindings {
			if oldKey == key || old.ScopeKey != incoming.ScopeKey || old.IP != incoming.IP || !old.ObservedAt.Before(incoming.ObservedAt) {
				continue
			}
			old.Withdrawn, old.ValidUntil = true, incoming.ObservedAt
			bindings[oldKey] = old
		}
	}
	for key := range bindings {
		pairKeys = append(pairKeys, key)
	}
	sort.Strings(pairKeys)
	pairs := make([]census.Binding, 0, len(pairKeys))
	for _, key := range pairKeys {
		pairs = append(pairs, bindings[key])
	}
	return toSpans(current), toSpans(buckets), pairs, nil
}

func writeCensusJSONChunks(ctx context.Context, tx *sql.Tx, query string, length int, slice func(int, int) any) (int64, error) {
	var written int64
	for start := 0; start < length; start += 500 {
		end := min(start+500, length)
		raw, err := json.Marshal(slice(start, end))
		if err != nil {
			return written, err
		}
		if len(raw) > 2*1024*1024 {
			return written, fmt.Errorf("census batch exceeds 2 MiB")
		}
		result, err := tx.ExecContext(ctx, query, raw)
		if err != nil {
			return written, err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return written, err
		}
		written += changed
	}
	return written, nil
}

const censusCurrentUpsert = `INSERT INTO passive_census_identifier_current
 (scope_key,sensor_id,campus_id,access_domain,vlan,vrf,kind,value,ip_family,random_mac,first_seen,last_seen,last_event_id,last_source)
 SELECT v.scope_key,v.sensor_id,v.campus_id,v.access_domain,v.vlan,v.vrf,v.kind,v.value,v.ip_family,v.random_mac,v.first_seen,v.last_seen,v.event_id,v.source
 FROM jsonb_to_recordset($1::jsonb) AS v(scope_key text,sensor_id text,campus_id text,access_domain text,vlan text,vrf text,kind text,value text,ip_family smallint,random_mac boolean,first_seen timestamptz,last_seen timestamptz,event_id text,source text)
 ON CONFLICT(scope_key,kind,value) DO UPDATE SET
  first_seen=least(passive_census_identifier_current.first_seen,EXCLUDED.first_seen),
  last_seen=greatest(passive_census_identifier_current.last_seen,EXCLUDED.last_seen),
  last_event_id=CASE WHEN (EXCLUDED.last_seen,EXCLUDED.last_event_id)>(passive_census_identifier_current.last_seen,passive_census_identifier_current.last_event_id) THEN EXCLUDED.last_event_id ELSE passive_census_identifier_current.last_event_id END,
  last_source=CASE WHEN (EXCLUDED.last_seen,EXCLUDED.last_event_id)>(passive_census_identifier_current.last_seen,passive_census_identifier_current.last_event_id) THEN EXCLUDED.last_source ELSE passive_census_identifier_current.last_source END,
  updated_at=now()
 WHERE EXCLUDED.first_seen<passive_census_identifier_current.first_seen OR EXCLUDED.last_seen>passive_census_identifier_current.last_seen OR (EXCLUDED.last_seen=passive_census_identifier_current.last_seen AND EXCLUDED.last_event_id>passive_census_identifier_current.last_event_id)`

const censusBucketUpsert = `INSERT INTO passive_census_identifier_5m(bucket_at,scope_key,kind,value,first_seen,last_seen,last_event_id)
 SELECT v.bucket_at,v.scope_key,v.kind,v.value,v.first_seen,v.last_seen,v.event_id
 FROM jsonb_to_recordset($1::jsonb) AS v(bucket_at timestamptz,scope_key text,kind text,value text,first_seen timestamptz,last_seen timestamptz,event_id text)
 ON CONFLICT(bucket_at,scope_key,kind,value) DO UPDATE SET
  first_seen=least(passive_census_identifier_5m.first_seen,EXCLUDED.first_seen),
  last_seen=greatest(passive_census_identifier_5m.last_seen,EXCLUDED.last_seen),
  last_event_id=CASE WHEN (EXCLUDED.last_seen,EXCLUDED.last_event_id)>(passive_census_identifier_5m.last_seen,passive_census_identifier_5m.last_event_id) THEN EXCLUDED.last_event_id ELSE passive_census_identifier_5m.last_event_id END
 WHERE EXCLUDED.first_seen<passive_census_identifier_5m.first_seen OR EXCLUDED.last_seen>passive_census_identifier_5m.last_seen OR (EXCLUDED.last_seen=passive_census_identifier_5m.last_seen AND EXCLUDED.last_event_id>passive_census_identifier_5m.last_event_id)`

const censusBindingPriorUpdate = `WITH incoming AS (
 SELECT DISTINCT ON(scope_key,ip) scope_key,ip,mac,observed_at FROM jsonb_to_recordset($1::jsonb)
 AS v(scope_key text,ip text,mac text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,event_id text,source text)
 WHERE source LIKE 'dhcp:%' AND NOT withdrawn ORDER BY scope_key,ip,observed_at DESC,event_id DESC
)
UPDATE passive_census_binding_current old SET valid_until=least(old.valid_until,i.observed_at),withdrawn=true,conflict=false,updated_at=now()
FROM incoming i WHERE old.scope_key=i.scope_key AND old.ip=i.ip AND old.mac<>i.mac AND old.observed_at<i.observed_at AND NOT old.withdrawn`

const censusBindingUpsert = `WITH incoming AS (
 SELECT * FROM jsonb_to_recordset($1::jsonb) AS v(scope_key text,ip text,mac text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,event_id text,source text)
)
INSERT INTO passive_census_binding_current(scope_key,ip,mac,observed_at,valid_until,withdrawn,conflict,evidence_event_id,source)
SELECT i.scope_key,i.ip,i.mac,i.observed_at,i.valid_until,i.withdrawn,
 (EXISTS(SELECT 1 FROM passive_census_binding_current old WHERE old.scope_key=i.scope_key AND old.ip=i.ip AND old.mac<>i.mac AND NOT old.withdrawn AND old.valid_until>i.observed_at)
 OR EXISTS(SELECT 1 FROM incoming peer WHERE peer.scope_key=i.scope_key AND peer.ip=i.ip AND peer.mac<>i.mac AND NOT peer.withdrawn AND peer.valid_until>i.observed_at)),i.event_id,i.source
FROM incoming i
ON CONFLICT(scope_key,ip,mac) DO UPDATE SET observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,conflict=EXCLUDED.conflict,evidence_event_id=EXCLUDED.evidence_event_id,source=EXCLUDED.source,updated_at=now()
WHERE (EXCLUDED.observed_at,EXCLUDED.evidence_event_id)>(passive_census_binding_current.observed_at,passive_census_binding_current.evidence_event_id)
 OR ((EXCLUDED.observed_at,EXCLUDED.evidence_event_id)=(passive_census_binding_current.observed_at,passive_census_binding_current.evidence_event_id)
 AND (EXCLUDED.valid_until,EXCLUDED.withdrawn,EXCLUDED.conflict,EXCLUDED.source) IS DISTINCT FROM
 (passive_census_binding_current.valid_until,passive_census_binding_current.withdrawn,passive_census_binding_current.conflict,passive_census_binding_current.source))`

// A late claim may arrive after a newer DHCP ACK was already projected. Only
// the IPs touched by this batch are inspected; no global binding rebuild runs.
const censusBindingSupersessionUpdate = `WITH affected AS (
 SELECT DISTINCT scope_key,ip FROM jsonb_to_recordset($1::jsonb) AS v(scope_key text,ip text,mac text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,event_id text,source text)
), newest_dhcp AS (
 SELECT DISTINCT ON (b.scope_key,b.ip) b.scope_key,b.ip,b.mac,b.observed_at
 FROM passive_census_binding_current b JOIN affected a ON a.scope_key=b.scope_key AND a.ip=b.ip
 WHERE b.source LIKE 'dhcp:%' AND NOT b.withdrawn
 ORDER BY b.scope_key,b.ip,b.observed_at DESC,b.evidence_event_id DESC
)
UPDATE passive_census_binding_current old SET valid_until=least(old.valid_until,n.observed_at),withdrawn=true,conflict=false,updated_at=now()
FROM newest_dhcp n WHERE old.scope_key=n.scope_key AND old.ip=n.ip AND old.mac<>n.mac AND old.observed_at<n.observed_at AND NOT old.withdrawn`

const censusBindingConflictRefresh = `WITH affected AS (
 SELECT DISTINCT scope_key,ip FROM jsonb_to_recordset($1::jsonb) AS v(scope_key text,ip text,mac text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,event_id text,source text)
), checked AS (
 SELECT b.scope_key,b.ip,b.mac,
  (NOT b.withdrawn AND b.valid_until>now() AND EXISTS(
   SELECT 1 FROM passive_census_binding_current peer
   WHERE peer.scope_key=b.scope_key AND peer.ip=b.ip AND peer.mac<>b.mac AND NOT peer.withdrawn AND peer.valid_until>now())) AS has_conflict
 FROM passive_census_binding_current b JOIN affected a ON a.scope_key=b.scope_key AND a.ip=b.ip
)
UPDATE passive_census_binding_current b SET conflict=c.has_conflict,updated_at=now()
FROM checked c WHERE b.scope_key=c.scope_key AND b.ip=c.ip AND b.mac=c.mac AND b.conflict IS DISTINCT FROM c.has_conflict`

func (s *DBStore) projectPassiveCensus(ctx context.Context, events []normalized.Event) error {
	if os.Getenv("PROXY_SENTINEL_PASSIVE_CENSUS_ENABLED") != "true" || len(events) == 0 {
		return nil
	}
	err := s.projectPassiveCensusBatch(ctx, events)
	if err != nil {
		oldest := time.Now().UTC()
		for _, event := range events {
			if at, parseErr := time.Parse(time.RFC3339Nano, event.Timestamp); parseErr == nil && at.Before(oldest) {
				oldest = at
			}
		}
		reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		message := err.Error()
		if len(message) > 512 {
			message = message[:512]
		}
		_, _ = s.pg.db.ExecContext(reportCtx, `INSERT INTO passive_census_runtime(sensor_id,oldest_pending_at,failed_batches,last_error) VALUES($1,$2,1,$3)
		 ON CONFLICT(sensor_id) DO UPDATE SET oldest_pending_at=least(coalesce(passive_census_runtime.oldest_pending_at,EXCLUDED.oldest_pending_at),EXCLUDED.oldest_pending_at),failed_batches=passive_census_runtime.failed_batches+1,last_error=EXCLUDED.last_error,updated_at=now()`, s.pg.sensorID, oldest, message)
	}
	return err
}

func (s *DBStore) projectPassiveCensusBatch(ctx context.Context, events []normalized.Event) error {
	prefixes, err := discovery.ParseCaptureCIDRs(os.Getenv("PROXY_SENTINEL_CENSUS_SITE_CIDRS"))
	if err != nil {
		return err
	}
	allowed := make([]string, len(prefixes))
	scopeVersion := census.ScopeVersion(prefixes)
	for i, prefix := range prefixes {
		allowed[i] = prefix.String()
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var earliest time.Time
	inserted := int64(0)
	for start := 0; start < len(events); start += 500 {
		end := min(start+500, len(events))
		chunk := events[start:end]
		current, buckets, bindings, coalesceErr := coalesceCensusIdentifiers(chunk, allowed)
		if coalesceErr != nil {
			return coalesceErr
		}
		first, last := time.Time{}, time.Time{}
		keys := make([]string, 0, len(chunk))
		for _, event := range chunk {
			at, parseErr := time.Parse(time.RFC3339Nano, event.Timestamp)
			if parseErr != nil {
				return parseErr
			}
			if first.IsZero() || at.Before(first) {
				first = at
			}
			if at.After(last) {
				last = at
			}
			keys = append(keys, event.Timestamp+"|"+event.EventID)
		}
		sort.Strings(keys)
		keyRaw, _ := json.Marshal(keys)
		hash := sha256.Sum256(append([]byte(scopeVersion+"|"), keyRaw...))
		payload, marshalErr := json.Marshal(censusTaskPayload{Current: current, Buckets: buckets, Bindings: bindings})
		if marshalErr != nil {
			return marshalErr
		}
		if len(payload) > 2*1024*1024 {
			return fmt.Errorf("census queued batch exceeds 2 MiB")
		}
		insertResult, insertErr := tx.ExecContext(ctx, `INSERT INTO passive_census_pending_batches(sensor_id,batch_key,scope_version,first_source_at,last_source_at,identifier_count,binding_count,payload,byte_size)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(sensor_id,batch_key) DO NOTHING`, s.pg.sensorID, hex.EncodeToString(hash[:]), scopeVersion, first, last, len(current), len(bindings), payload, len(payload))
		if insertErr != nil {
			return insertErr
		}
		changed, countErr := insertResult.RowsAffected()
		if countErr != nil {
			return countErr
		}
		if changed > 0 {
			inserted += changed
			if earliest.IsZero() || first.Before(earliest) {
				earliest = first
			}
		}
	}
	if inserted == 0 {
		return tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO passive_census_runtime(sensor_id,scope_version,oldest_pending_at,updated_at) VALUES($1,$2,$3,now())
 ON CONFLICT(sensor_id) DO UPDATE SET scope_version=EXCLUDED.scope_version,oldest_pending_at=least(coalesce(passive_census_runtime.oldest_pending_at,EXCLUDED.oldest_pending_at),EXCLUDED.oldest_pending_at),updated_at=now()
 WHERE passive_census_runtime.scope_version IN ('',EXCLUDED.scope_version)`, s.pg.sensorID, scopeVersion, earliest)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return fmt.Errorf("census CIDR scope changed; controlled rebuild required")
	}
	return tx.Commit()
}
