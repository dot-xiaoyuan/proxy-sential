package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func TestPassiveLatestTouchPostgresMatchingKeys(t *testing.T) {
	db := privateMigratedTestPostgres(t).db
	ctx := context.Background()
	at := time.Date(2026, 11, 25, 4, 0, 0, 123456000, time.UTC)
	fixtures := []struct {
		key, id string
		delta   time.Duration
	}{
		{"due", "shared", -time.Minute},
		{"throttled", "shared", -59 * time.Second},
		{"future", "shared", 10 * time.Second},
		{"other", "unrelated", -time.Minute},
	}
	for _, v := range fixtures {
		_, err := db.Exec(`INSERT INTO discovery_observation_latest(device_key,source_id,origin,service_type,port,id,observed_at,valid_until,withdrawn,data)
   VALUES('k',$1,'arp','','',$2,$3,$4,false,jsonb_build_object('name',$1::text))`, v.key, v.id, at.Add(v.delta), at.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(source string, seen, until time.Time) {
		t.Helper()
		var actualSeen, actualUntil time.Time
		var doc string
		err := db.QueryRow(`SELECT observed_at,valid_until,data->>'name'
FROM discovery_observation_latest WHERE device_key='k' AND source_id=$1`, source).Scan(&actualSeen, &actualUntil, &doc)
		if err != nil || !seen.Equal(actualSeen) || !until.Equal(actualUntil) || doc != source {
			t.Fatalf("%s: seen=%s until=%s retained=%q err=%v", source, actualSeen, actualUntil, doc, err)
		}
	}
	touch := func(seen, until time.Time) {
		t.Helper()
		if err := touchPassiveLatest(ctx, db, []discovery.Observation{{ID: "shared", ObservedAt: seen, ValidUntil: until}}); err != nil {
			t.Fatal(err)
		}
	}
	// The one-minute condition and expiry guard apply per retained key.
	touch(at, at.Add(2*time.Hour))
	check("due", at, at.Add(2*time.Hour))
	check("throttled", at.Add(-59*time.Second), at.Add(time.Hour))
	check("future", at.Add(10*time.Second), at.Add(time.Hour))
	touch(at, at.Add(15*time.Minute))
	touch(at.Add(-time.Second), at.Add(-time.Second))
	check("due", at, at.Add(15*time.Minute))
	check("throttled", at, at.Add(15*time.Minute))
	check("future", at.Add(10*time.Second), at.Add(time.Hour))
	touch(at.Add(2*time.Minute), at.Add(3*time.Hour))
	for _, source := range []string{"due", "throttled", "future"} {
		check(source, at.Add(2*time.Minute), at.Add(3*time.Hour))
	}
	check("other", at.Add(-time.Minute), at.Add(time.Hour))
}

func TestPassiveLatestTouchARPIncludesThrottledHistory(t *testing.T) {
	pg := privateMigratedTestPostgres(t)
	store := &DBStore{pg: pg}
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	recent := discovery.Observation{
		ID: "recent", SourceID: "mirror", Origin: "arp", IP: "192.0.2.1", MAC: "02:00:00:00:00:01",
		ObservedAt: at, ValidUntil: at.Add(time.Hour),
	}
	if _, err := store.insertPassiveARPBatch(ctx, pg.db, []discovery.Observation{recent}); err != nil {
		t.Fatal(err)
	}
	recent.ObservedAt = at.Add(time.Second)
	recent.ValidUntil = at.Add(time.Minute)
	fresh := recent
	fresh.ID, fresh.IP, fresh.MAC = "fresh", "192.0.2.2", "02:00:00:00:00:02"
	refreshed, err := store.insertPassiveARPBatch(ctx, pg.db, []discovery.Observation{recent, fresh})
	if err != nil || len(refreshed) != 1 || refreshed[0].ID != fresh.ID {
		t.Fatalf("ARP history refresh: got %v, err=%v", refreshed, err)
	}
	var historySeen, latestSeen, latestExpiry time.Time
	err = pg.db.QueryRowContext(ctx, `SELECT h.observed_at,l.observed_at,l.valid_until
FROM discovery_observations h JOIN discovery_observation_latest l ON l.id=h.id WHERE h.id=$1`, recent.ID).Scan(&historySeen, &latestSeen, &latestExpiry)
	if err != nil || !historySeen.Equal(at) || !latestSeen.Equal(recent.ObservedAt) || !latestExpiry.Equal(recent.ValidUntil) {
		t.Fatalf("history seen=%s, latest seen=%s expiry=%s err=%v", historySeen, latestSeen, latestExpiry, err)
	}
}

func TestPassiveLatestTouchPayloadPreservesOrderAndOnlyClocks(t *testing.T) {
	at := time.Date(2026, 11, 25, 8, 9, 10, 123456789, time.FixedZone("site", 8*3600))
	observations := []discovery.Observation{
		{ID: "z", ObservedAt: at, ValidUntil: at.Add(time.Hour), Evidence: normalized.Event{Payload: map[string]any{"unused": make(chan int)}}},
		{ID: "a", ObservedAt: at.Add(time.Second), ValidUntil: at},
		{ID: "z", ObservedAt: at, ValidUntil: at},
	}
	encoded, err := marshalPassiveLatestTouches(observations)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]string
	if err = json.Unmarshal(encoded, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(observations) {
		t.Fatalf("got %d rows", len(rows))
	}
	for i, o := range observations {
		want := map[string]string{
			"id": o.ID, "observed_at": o.ObservedAt.Format(time.RFC3339Nano),
			"valid_until": o.ValidUntil.Format(time.RFC3339Nano),
		}
		if !reflect.DeepEqual(rows[i], want) {
			t.Fatalf("row %d: got %v, want %v", i, rows[i], want)
		}
	}
}

func BenchmarkPassiveLatestTouch1500(b *testing.B) {
	const n = 1500
	at := time.Date(2026, 11, 25, 8, 9, 10, 123456000, time.UTC)
	observations := make([]discovery.Observation, 0, n)
	legacy := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(i))))
		seen := at.Add(time.Duration(i) * time.Millisecond)
		o := discovery.Observation{
			ID: "discovery-" + digest, EventID: "wire-" + digest, SourceID: "mirror",
			Node: "sensor", Site: "campus", Domain: "mirror", VLAN: fmt.Sprint(i % 71),
			Origin: "http_device", IP: fmt.Sprintf("10.0.%d.%d", i/255, i%255+1),
			ObservedAt: seen, ValidUntil: seen.Add(time.Hour),
			Evidence: normalized.Event{
				EventID: digest, Source: "zeek",
				Payload: map[string]any{"http_method": "GET", "service_instance": "device", "detail": ""},
			},
		}
		// Match the roughly 1.5 KiB retained discovery documents in the field
		// sample without copying any raw field evidence into the benchmark.
		raw, err := json.Marshal(o)
		if err != nil {
			b.Fatal(err)
		}
		o.Evidence.Payload["detail"] = strings.Repeat(digest, 24)[:max(0, 1474-len(raw))]
		raw, err = json.Marshal(o)
		if err != nil {
			b.Fatal(err)
		}
		observations = append(observations, o)
		legacy = append(legacy, map[string]any{
			"id": o.ID, "device_key": o.Key(), "source_id": o.SourceID, "origin": o.Origin,
			"observed_at": o.ObservedAt, "valid_until": o.ValidUntil, "withdrawn": o.Withdrawn,
			"data": json.RawMessage(raw), "service_instance": "device",
		})
	}
	for _, version := range []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{"full", func() ([]byte, error) { return json.Marshal(legacy) }},
		{"clocks", func() ([]byte, error) { return marshalPassiveLatestTouches(observations) }},
	} {
		for _, compressed := range []bool{false, true} {
			name := version.name + "/json"
			if compressed {
				name += "+gzip"
			}
			b.Run(name, func(b *testing.B) {
				var size int
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					raw, err := version.marshal()
					if err != nil {
						b.Fatal(err)
					}
					size = len(raw)
					if compressed {
						var out bytes.Buffer
						writer := gzip.NewWriter(&out)
						if _, err = writer.Write(raw); err != nil {
							b.Fatal(err)
						}
						if err = writer.Close(); err != nil {
							b.Fatal(err)
						}
						size = out.Len()
					}
				}
				b.ReportMetric(float64(size), "input-B/op")
			})
		}
	}
}
