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
