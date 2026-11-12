package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/behaviorreport"
	"proxy-sentinel/internal/store"
)

// behaviorReportFakeStore implements the slice of storage the worker uses.
// store.Reader is embedded only to satisfy the server field type.
type behaviorReportFakeStore struct {
	store.Reader
	mu         sync.Mutex
	channels   []store.BehaviorReportChannel
	candidates []store.BehaviorReportCandidate
	enqueued   []store.BehaviorReportOutboxRow
	claimed    [][]store.BehaviorReportOutboxRow
	sent       []string
	failed     []string
	retried    []string
	lastBatch  []behaviorreport.Event
	seekRows   []store.BehaviorReportOutboxRow
}

func (f *behaviorReportFakeStore) ListBehaviorReportChannels(context.Context) ([]store.BehaviorReportChannel, error) {
	return f.channels, nil
}

func (f *behaviorReportFakeStore) GetBehaviorReportChannel(_ context.Context, id string) (store.BehaviorReportChannel, error) {
	for _, channel := range f.channels {
		if channel.ChannelID == id {
			return channel, nil
		}
	}
	return store.BehaviorReportChannel{}, nil
}

func (f *behaviorReportFakeStore) UpsertBehaviorReportChannel(context.Context, behaviorreport.Channel, string, string, bool) (store.BehaviorReportChannel, error) {
	return store.BehaviorReportChannel{}, nil
}

func (f *behaviorReportFakeStore) DeleteBehaviorReportChannel(context.Context, string) error {
	return nil
}

func (f *behaviorReportFakeStore) ListBehaviorReportCandidates(context.Context, time.Time, int) ([]store.BehaviorReportCandidate, error) {
	return f.candidates, nil
}

func (f *behaviorReportFakeStore) EnqueueBehaviorReport(_ context.Context, row store.BehaviorReportOutboxRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enqueued = append(f.enqueued, row)
	return nil
}

func (f *behaviorReportFakeStore) ClaimBehaviorReportBatch(_ context.Context, channelID string, batchSize int) ([]store.BehaviorReportOutboxRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.claimed) == 0 {
		return nil, nil
	}
	rows := f.claimed[0]
	f.claimed = f.claimed[1:]
	return rows, nil
}

func (f *behaviorReportFakeStore) MarkBehaviorReportSent(_ context.Context, row store.BehaviorReportOutboxRow, _ int, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, row.ReportID)
	return nil
}

func (f *behaviorReportFakeStore) MarkBehaviorReportFailed(_ context.Context, row store.BehaviorReportOutboxRow, _ int, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, row.ReportID)
	return nil
}

func (f *behaviorReportFakeStore) MarkBehaviorReportRetry(_ context.Context, row store.BehaviorReportOutboxRow, _ int, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retried = append(f.retried, row.ReportID)
	return nil
}

func (f *behaviorReportFakeStore) ListBehaviorReportOutbox(context.Context, string, int, int) ([]store.BehaviorReportOutboxRow, int, error) {
	return nil, 0, nil
}

func (f *behaviorReportFakeStore) ListBehaviorReportOutboxSeek(_ context.Context, status string, _ time.Time, at time.Time, id string, limit int) ([]store.BehaviorReportOutboxRow, error) {
	items := []store.BehaviorReportOutboxRow{}
	for _, row := range f.seekRows {
		rowAt, _ := time.Parse(time.RFC3339Nano, row.OccurredAt)
		if status != "" && row.Status != status {
			continue
		}
		if id != "" && !(rowAt.Before(at) || rowAt.Equal(at) && row.ReportID < id) {
			continue
		}
		items = append(items, row)
		if len(items) == limit+1 {
			break
		}
	}
	return items, nil
}

func TestBehaviorReportSeekPagination(t *testing.T) {
	at := time.Date(2026, 11, 12, 1, 0, 0, 123456000, time.UTC).Format(time.RFC3339Nano)
	fake := &behaviorReportFakeStore{seekRows: []store.BehaviorReportOutboxRow{
		{ReportID: "c", Status: "recorded", OccurredAt: at},
		{ReportID: "b", Status: "recorded", OccurredAt: at},
		{ReportID: "a", Status: "recorded", OccurredAt: at},
	}}
	s := &Server{}
	seen := []string{}
	cursor := ""
	for page := 0; page < 2; page++ {
		path := "/api/v1/behavior-reports/outbox?seek=1&status=recorded&limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		w := httptest.NewRecorder()
		s.handleBehaviorReportOutbox(w, httptest.NewRequest("GET", path, nil), fake)
		if w.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", page, w.Code, w.Body.String())
		}
		var body struct {
			Items      []store.BehaviorReportOutboxRow `json:"items"`
			NextCursor string                          `json:"next_cursor"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		for _, row := range body.Items {
			seen = append(seen, row.ReportID)
		}
		cursor = body.NextCursor
	}
	if len(seen) != 3 || seen[0] != "c" || seen[1] != "b" || seen[2] != "a" || cursor != "" {
		t.Fatalf("unexpected pages: %v next=%q", seen, cursor)
	}
}

func (f *behaviorReportFakeStore) GetBehaviorReportOutbox(context.Context, string) (store.BehaviorReportOutboxRow, []store.BehaviorReportAttempt, error) {
	return store.BehaviorReportOutboxRow{}, nil, nil
}

func (f *behaviorReportFakeStore) RequeueBehaviorReport(context.Context, string) error { return nil }
func (f *behaviorReportFakeStore) CancelBehaviorReport(context.Context, string) error  { return nil }

func TestBehaviorReportEventTypeMapping(t *testing.T) {
	cases := map[string]string{
		"internal_target_access":     behaviorreport.EventPoisonBehavior,
		"proxy_protocol_transaction": behaviorreport.EventProxyBehavior,
		"ai_relay_domain_usage":      behaviorreport.EventAIRelayAudit,
	}
	for evidenceType, expected := range cases {
		got, ok := behaviorReportEventType(evidenceType)
		if !ok || got != expected {
			t.Fatalf("%s must map to %s, got %s (%v)", evidenceType, expected, got, ok)
		}
	}
	if _, ok := behaviorReportEventType("ttl_clusters"); ok {
		t.Fatal("weak unrelated evidence must not be reported northbound")
	}
}

func TestBehaviorReportProducersQueueOncePerChannel(t *testing.T) {
	fake := &behaviorReportFakeStore{
		channels: []store.BehaviorReportChannel{
			{ChannelID: "platform-a", Enabled: true},
			{ChannelID: "platform-b", Enabled: true},
			{ChannelID: "disabled", Enabled: false},
		},
		candidates: []store.BehaviorReportCandidate{
			{EvidenceID: "ev-1", IP: "10.155.9.9", EventType: "internal_target_access", Window: "w1", OccurredAt: "2026-10-01T12:00:00Z"},
			{EvidenceID: "ev-2", IP: "10.155.9.10", EventType: "ttl_clusters", Window: "w1", OccurredAt: "2026-10-01T12:00:00Z"},
		},
	}
	server := &Server{reader: fake}
	server.processBehaviorReports(time.Now().UTC())
	if len(fake.enqueued) != 2 {
		t.Fatalf("only enabled channels receive both reportable events: %+v", fake.enqueued)
	}
	seen := map[string]bool{}
	for _, row := range fake.enqueued {
		if row.EventType != behaviorreport.EventPoisonBehavior {
			t.Fatalf("unexpected event type: %+v", row)
		}
		if row.ChannelID == "disabled" {
			t.Fatalf("disabled channel received a report: %+v", row)
		}
		if seen[row.IdempotencyKey] {
			t.Fatalf("idempotency key reused: %+v", row)
		}
		seen[row.IdempotencyKey] = true
	}
}

func TestBehaviorReportDeliveryMarksSentAndRetry(t *testing.T) {
	accepted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"remote-1"}`))
	}))
	defer accepted.Close()
	sealed, err := (&Server{actionMasterKey: []byte("behavior-report-test-key")}).encryptConnectorSecret("credential")
	if err != nil {
		t.Fatal(err)
	}
	channel := store.BehaviorReportChannel{ChannelID: "c1", Name: "n", EndpointURL: accepted.URL, AuthType: behaviorreport.AuthNone, Enabled: true, BatchSize: 10, TimeoutSeconds: 5, SuccessStatusCodes: []int{200}, EncryptedSecret: sealed}
	fake := &behaviorReportFakeStore{
		channels: []store.BehaviorReportChannel{channel},
		claimed: [][]store.BehaviorReportOutboxRow{{
			{ReportID: "r1", ChannelID: "c1", EventType: behaviorreport.EventPoisonBehavior, IP: "10.0.0.1", OccurredAt: "2026-10-01T12:00:00Z", Attempts: 1},
			{ReportID: "r2", ChannelID: "c1", EventType: behaviorreport.EventProxyBehavior, IP: "10.0.0.2", OccurredAt: "2026-10-01T12:00:00Z", Attempts: 1},
		}},
	}
	server := &Server{reader: fake, actionMasterKey: []byte("behavior-report-test-key")}
	server.processBehaviorReports(time.Now().UTC())
	if len(fake.sent) != 2 {
		t.Fatalf("accepted batch must be marked sent: %+v", fake.sent)
	}
	if len(fake.retried) != 0 || len(fake.failed) != 0 {
		t.Fatalf("nothing should fail after acceptance: %+v %+v", fake.retried, fake.failed)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer failing.Close()
	channel.EndpointURL = failing.URL
	fake2 := &behaviorReportFakeStore{
		channels: []store.BehaviorReportChannel{channel},
		claimed:  [][]store.BehaviorReportOutboxRow{{{ReportID: "r3", ChannelID: "c1", EventType: behaviorreport.EventProxyBehavior, IP: "10.0.0.3", OccurredAt: "2026-10-01T12:00:00Z", Attempts: 1}}},
	}
	(&Server{reader: fake2, actionMasterKey: []byte("behavior-report-test-key")}).processBehaviorReports(time.Now().UTC())
	if len(fake2.retried) != 1 || len(fake2.failed) != 0 {
		t.Fatalf("transient failure must be retried: %+v %+v", fake2.retried, fake2.failed)
	}
}

func TestBehaviorReportExhaustedAttemptsFail(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer failing.Close()
	channel := store.BehaviorReportChannel{ChannelID: "c1", Name: "n", EndpointURL: failing.URL, AuthType: behaviorreport.AuthNone, Enabled: true, BatchSize: 10, TimeoutSeconds: 5, SuccessStatusCodes: []int{200}}
	fake := &behaviorReportFakeStore{
		channels: []store.BehaviorReportChannel{channel},
		claimed:  [][]store.BehaviorReportOutboxRow{{{ReportID: "r4", ChannelID: "c1", EventType: behaviorreport.EventProxyBehavior, IP: "10.0.0.4", OccurredAt: "2026-10-01T12:00:00Z", Attempts: behaviorreport.MaxAttempts}}},
	}
	(&Server{reader: fake, actionMasterKey: []byte("behavior-report-test-key")}).processBehaviorReports(time.Now().UTC())
	if len(fake.failed) != 1 {
		t.Fatalf("exhausted attempts must fail permanently: %+v (retried=%+v)", fake.failed, fake.retried)
	}
}
