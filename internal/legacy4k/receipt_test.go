package legacy4k

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/identityprotocol"
	"testing"
)

func TestSenderRejectsUnverifiableSuccess(t *testing.T) {
	for _, body := range []string{"", `{}`, `{"batch_id":"b","status":"failed"}`, `{"batch_id":"other","status":"completed","source":"legacy-4k","sensor_id":"s","read":1}`, `{"batch_id":"b","status":"completed","source":"legacy-4k","sensor_id":"s","read":2}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202); _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			if err := (Sender{Endpoint: server.URL, SensorID: "s"}).Send(context.Background(), []map[string]string{{"ip": "10.0.0.1"}}, "b"); err == nil {
				t.Fatal("unverified receipt accepted")
			}
		})
	}
}

func TestDurableSenderRequiresExactReceipt(t *testing.T) {
	for _, mutation := range []string{"valid", "empty", "hash", "id", "count", "protocol", "accepted", "timestamp"} {
		t.Run(mutation, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var batch identityprotocol.Request
				if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
					t.Error(err)
				}
				if r.URL.Path != "/api/v1/integrations/identity/event-batches" {
					t.Error("legacy endpoint used")
				}
				receipt := identityprotocol.Receipt{ProtocolVersion: 2, BatchID: r.Header.Get("Idempotency-Key"), ContentSHA256: batch.Hash(), RecordCount: len(batch.Records), DurablyAccepted: true, AcceptedAt: "2026-10-13T08:00:00Z"}
				switch mutation {
				case "empty":
					w.WriteHeader(202)
					return
				case "hash":
					receipt.ContentSHA256 = "wrong"
				case "id":
					receipt.BatchID = "wrong"
				case "count":
					receipt.RecordCount++
				case "protocol":
					receipt.ProtocolVersion = 1
				case "accepted":
					receipt.DurablyAccepted = false
				case "timestamp":
					receipt.AcceptedAt = ""
				}
				_ = json.NewEncoder(w).Encode(receipt)
			}))
			defer server.Close()
			err := (Sender{Endpoint: server.URL, Durable: true, SensorID: "s"}).Send(context.Background(), []map[string]string{{"ip": "192.0.2.1"}}, "b")
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("receipt %s: %v", mutation, err)
			}
		})
	}
}
