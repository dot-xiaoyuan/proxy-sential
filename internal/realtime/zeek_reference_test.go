package realtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestZeekRawReferenceSurvivesBatchRetryAndKeepsOriginalRecordHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sip.log")
	raw := `{"ts":1785232800,"uid":"C1","id.orig_h":"10.0.0.2","id.resp_h":"10.0.0.3","method":"REGISTER","user_agent":"Huawei eSpace 7910 V200R003C00"}`
	if err := os.WriteFile(path, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	options := Options{SensorID: "test", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}
	source := Source{Kind: "zeek-sip", Path: path}
	if err := ProcessOnce(context.Background(), backend, options, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 1 {
		t.Fatalf("missing event: %+v", backend.events)
	}
	e := backend.events[0]
	digest := sha256.Sum256([]byte(raw))
	if e.RawRef["content_sha256"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("record digest not original: %+v", e.RawRef)
	}
	ref, ok := e.RawRef["ingest_source_ref"].(map[string]any)
	if !ok || ref["source"] != path || ref["file_id"] != backend.batches[0].FileID || ref["end_offset"] != int64(len(raw)+1) || ref["content_sha256"] != backend.batches[0].Checksum {
		t.Fatalf("batch provenance missing: %+v", ref)
	}
	backend.found = false
	if err := ProcessOnce(context.Background(), backend, options, source); err != nil {
		t.Fatal(err)
	}
	again := backend.events[1]
	if again.EventID != e.EventID || again.RawRef["content_sha256"] != e.RawRef["content_sha256"] || again.RawRef["ingest_source_ref"].(map[string]any)["batch_id"] != ref["batch_id"] {
		t.Fatal("retry changed original reference")
	}
}

func TestSSDPSourceFileReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signals.jsonl")
	raw := `{"schema_version":"v1","event_id":"old-advert","type":"device","timestamp":"2026-11-22T12:00:00Z","source":"packet-sidecar","source_event_type":"ssdp","subject":{"ip":"192.0.2.1"},"payload":{"is_announcement":true}}`
	if err := os.WriteFile(path, []byte(raw+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{}
	opts := Options{SensorID: "campus", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}
	for i := 0; i < 2; i++ {
		b.found = false
		if err := ProcessOnce(context.Background(), b, opts, Source{Kind: "device-signals", Path: path}); err != nil {
			t.Fatal(err)
		}
		e := b.events[i]
		sum := sha256.Sum256([]byte(raw))
		ref, _ := e.RawRef["ingest_source_ref"].(map[string]any)
		if e.EventID != "old-advert" || e.RawRef["content_sha256"] != hex.EncodeToString(sum[:]) || ref["file_id"] != b.batches[0].FileID {
			t.Fatalf("missing original JSONL reference: %+v", e.RawRef)
		}
	}
}

func TestPacketDiscoveryReferenceIsOptInAndVerifiable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signals.jsonl")
	raw := `{"schema_version":"v1","event_id":"control-one","type":"device","timestamp":"2026-11-22T12:00:00Z","source":"packet-sidecar","source_event_type":"sadp","subject":{"ip":"192.0.2.1"},"raw_ref":{"payload_sha256":"payload-digest"}}`
	if err := os.WriteFile(path, []byte(raw+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind          string
		enabled, want bool
	}{{"device-signals", false, false}, {"device-signals", true, true}, {"shared-device-signals", true, false}} {
		backend := &fakeBackend{}
		opts := Options{SensorID: "campus", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}
		if err := ProcessOnce(context.Background(), backend, opts, Source{Kind: tc.kind, Path: path, ArchivePacketRecords: tc.enabled}); err != nil {
			t.Fatal(err)
		}
		event := backend.events[0]
		ref, present := event.RawRef["ingest_source_ref"].(map[string]any)
		if event.RawRef["payload_sha256"] != "payload-digest" || present != tc.want {
			t.Fatalf("kind %s enabled %t: %+v", tc.kind, tc.enabled, event.RawRef)
		}
		if tc.want {
			sum := sha256.Sum256([]byte(raw))
			if event.RawRef["content_sha256"] != hex.EncodeToString(sum[:]) || ref["batch_id"] != backend.batches[0].BatchID {
				t.Fatalf("record or batch does not match input: %+v", event.RawRef)
			}
		} else if event.RawRef["content_sha256"] != nil {
			t.Fatal("record digest unexpectedly introduced")
		}
	}
}
