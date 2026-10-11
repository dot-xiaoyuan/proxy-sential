package behaviorreport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testChannel(endpoint string) Channel {
	return Channel{
		ChannelID: "ncu-behavior", Name: "网络安全行为上报", EndpointURL: endpoint,
		AuthType: AuthOAuth2Client, TokenEndpoint: "", TokenMethod: http.MethodGet,
		SourceSystemIP: "10.0.0.1", SourceSystemName: "校园 DPI 系统",
		BatchSize: 100, TimeoutSeconds: 5,
		FieldMapping: map[string]string{
			"behavior_type":      "event_type",
			"account":            "account",
			"source_ip":          "ip",
			"occurred_at":        "occurred_at",
			"source_system_name": "=校园 DPI 系统",
			"target":             "target",
			"detail_protocol":    "detail.protocol",
		},
		SuccessStatusCodes: []int{200},
	}
}

func TestValidateChannelRejectsBadConfiguration(t *testing.T) {
	valid := testChannel("https://example.invalid/report")
	valid.TokenEndpoint = "https://example.invalid/token"
	if err := ValidateChannel(&valid); err != nil {
		t.Fatalf("valid channel rejected: %v", err)
	}
	invalid := []Channel{
		{ChannelID: "c", Name: "n", EndpointURL: "ftp://x", AuthType: AuthNone},
		{ChannelID: "c", Name: "n", EndpointURL: "https://x", AuthType: "kerberos"},
		{ChannelID: "c", Name: "n", EndpointURL: "https://x", AuthType: AuthOAuth2Client},
		{ChannelID: "c", Name: "n", EndpointURL: "https://x", AuthType: AuthNone, SuccessStatusCodes: []int{9999}},
	}
	for _, item := range invalid {
		candidate := item
		if err := ValidateChannel(&candidate); err == nil {
			t.Fatalf("invalid channel accepted: %+v", item)
		}
	}
}

func TestChannelRedactedHidesSecret(t *testing.T) {
	channel := testChannel("https://example.invalid/report")
	channel.Secret = "s3cret"
	channel.EncryptedSecret = "sealed"
	redacted := channel.Redacted()
	if redacted.Secret != "" || redacted.EncryptedSecret != "" || !redacted.HasSecret {
		t.Fatalf("secret leaked: %+v", redacted)
	}
}

func TestPayloadMapsFieldsAndUsesLegacyBehaviourVocabulary(t *testing.T) {
	channel := testChannel("https://example.invalid/report")
	channel.SuccessStatusCodes = []int{200}
	payload, err := channel.Payload([]Event{{
		ReportID: "r1", EventType: EventPoisonBehavior, IP: "10.155.9.9", AccountID: "u1",
		Target: "10.155.32.11", TargetType: "ip", OccurredAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		Detail: map[string]string{"protocol": "tcp"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if payload["behavior_type"] != "malware" {
		t.Fatalf("poison behaviour must map to the platform malware type: %+v", payload)
	}
	if payload["account"] != "u1" || payload["source_ip"] != "10.155.9.9" || payload["target"] != "10.155.32.11" {
		t.Fatalf("mapping not applied: %+v", payload)
	}
	if payload["source_system_name"] != "校园 DPI 系统" || payload["detail_protocol"] != "tcp" {
		t.Fatalf("constant and detail mappings not applied: %+v", payload)
	}
	if payload["source_system_ip"] != "10.0.0.1" {
		t.Fatalf("source system ip must fall back to the channel: %+v", payload)
	}
}

func TestPayloadBatchesMultipleEvents(t *testing.T) {
	channel := testChannel("https://example.invalid/report")
	payload, err := channel.Payload([]Event{
		{EventType: EventProxyBehavior, IP: "10.0.0.2", OccurredAt: time.Now()},
		{EventType: EventAIRelayAudit, IP: "10.0.0.3", OccurredAt: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	items, ok := payload["items"].([]map[string]any)
	if !ok || len(items) != 2 {
		t.Fatalf("batch payload must carry items: %+v", payload)
	}
}

func TestSendFetchesTokenAndTreatsOnlyConfiguredCodesAsSuccess(t *testing.T) {
	var tokenCalls, reportCalls int
	var seenAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenCalls++
			if r.Header.Get("X-Proxy-Sentinel-Credential") == "" {
				t.Error("token request must carry the configured credential")
			}
			_, _ = w.Write([]byte(`{"data":{"access_token":"tok-9"}}`))
		case "/report":
			reportCalls++
			seenAuth = r.Header.Get("Authorization")
			raw, _ := io.ReadAll(r.Body)
			var decoded map[string]any
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Errorf("payload is not JSON: %v", err)
			}
			if decoded["behavior_type"] != "proxy" {
				t.Errorf("unexpected payload: %+v", decoded)
			}
			_, _ = w.Write([]byte(`{"id":"remote-1"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	channel := testChannel(server.URL + "/report")
	channel.TokenEndpoint = server.URL + "/token"
	sender, err := NewSender(channel, "credential")
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.Send(context.Background(), []Event{{ReportID: "r1", EventType: EventProxyBehavior, IP: "10.0.0.2", OccurredAt: time.Now()}})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if tokenCalls != 1 || reportCalls != 1 || seenAuth != "Bearer tok-9" {
		t.Fatalf("unexpected calls: token=%d report=%d auth=%q", tokenCalls, reportCalls, seenAuth)
	}
	if result.RemoteID != "remote-1" {
		t.Fatalf("remote id not captured: %+v", result)
	}
}

func TestSendClassifiesRejections(t *testing.T) {
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer rejecting.Close()
	channel := testChannel(rejecting.URL)
	channel.AuthType = AuthNone
	sender, err := NewSender(channel, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sender.Send(context.Background(), []Event{{EventType: EventProxyBehavior, IP: "10.0.0.2", OccurredAt: time.Now()}}); !IsPermanent(err) {
		t.Fatalf("4xx must be permanent, got %v", err)
	}

	transient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer transient.Close()
	channel = testChannel(transient.URL)
	channel.AuthType = AuthNone
	sender, _ = NewSender(channel, "")
	if _, err = sender.Send(context.Background(), []Event{{EventType: EventProxyBehavior, IP: "10.0.0.2", OccurredAt: time.Now()}}); err == nil || IsPermanent(err) {
		t.Fatalf("5xx must stay retryable, got %v", err)
	}
}

func TestBackoffAndIdempotencyAreStable(t *testing.T) {
	if Backoff(1) != time.Second || Backoff(2) != 2*time.Second || Backoff(60) != time.Hour {
		t.Fatalf("unexpected backoff: %v %v %v", Backoff(1), Backoff(2), Backoff(60))
	}
	first := IdempotencyKey(EventPoisonBehavior, "10.0.0.1", "10.0.0.2", "w1")
	if first != IdempotencyKey(EventPoisonBehavior, "10.0.0.1", "10.0.0.2", "w1") {
		t.Fatal("idempotency key must be stable")
	}
	if first == IdempotencyKey(EventPoisonBehavior, "10.0.0.1", "10.0.0.2", "w2") {
		t.Fatal("idempotency key must change with the window")
	}
}
