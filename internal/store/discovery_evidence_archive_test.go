package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func TestDiscoveryArchiveRejectsUnreadableBodyDespiteMatchingReceipt(t *testing.T) {
	event := normalized.Event{EventID: "evidence-one", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	receiptHash := hex.EncodeToString(digest[:])
	accepted := time.Now().UTC().Truncate(time.Microsecond)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"ordinal":0,"content_hash":"%s","event_id":"evidence-one","accepted_us":%d,"document_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`+"\n", receiptHash, accepted.UnixMicro())
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	err = ch.WriteDiscoveryEvidenceArchive(context.Background(), "batch", accepted, []normalized.Event{event})
	if !errors.Is(err, discovery.ErrDiscoveryContentConflict) {
		t.Fatalf("archive accepted a receipt with an unreadable body: %v", err)
	}
}
