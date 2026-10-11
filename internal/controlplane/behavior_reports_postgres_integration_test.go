package controlplane

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/behaviorreport"
	"proxy-sentinel/internal/store"
)

func requireOwnedBehaviorReportDatabase(t *testing.T) (*store.PostgresStore, context.Context) {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_acceptance_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("owned isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := store.NewPostgresStore(store.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	// These acceptance tests share one database with the rest of the suite, so
	// they must be re-runnable: clear only their own rows.
	cleanup, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cleanup.ExecContext(ctx, `DELETE FROM behavior_report_attempts; DELETE FROM behavior_report_outbox; DELETE FROM behavior_report_channels;`); err != nil {
		cleanup.Close()
		t.Fatal(err)
	}
	cleanup.Close()
	return pg, ctx
}

func TestBehaviorReportChannelSecretAndOutboxLifecycle(t *testing.T) {
	pg, ctx := requireOwnedBehaviorReportDatabase(t)
	server := &Server{actionMasterKey: []byte("behavior-report-integration-key")}
	sealed, err := server.encryptConnectorSecret("platform-credential")
	if err != nil {
		t.Fatal(err)
	}
	channel := behaviorreport.Channel{
		ChannelID: "ncu-platform", Name: "网络安全行为上报", EndpointURL: "https://example.invalid/report",
		AuthType: behaviorreport.AuthOAuth2Client, TokenEndpoint: "https://example.invalid/token", TokenMethod: http.MethodGet,
		SourceSystemIP: "10.0.0.1", SourceSystemName: "校园 DPI 系统",
		BatchSize: 50, TimeoutSeconds: 5, SuccessStatusCodes: []int{200},
		FieldMapping: map[string]string{"behavior_type": "event_type", "account": "account"},
		Enabled:      true,
	}
	saved, err := pg.UpsertBehaviorReportChannel(ctx, channel, sealed, "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	if saved.EncryptedSecret != sealed || !saved.HasSecret {
		t.Fatalf("sealed secret not persisted: %+v", saved)
	}
	stored, err := pg.GetBehaviorReportChannel(ctx, "ncu-platform")
	if err != nil || stored.FieldMapping["behavior_type"] != "event_type" || len(stored.SuccessStatusCodes) != 1 {
		t.Fatalf("channel did not round-trip: %+v %v", stored, err)
	}
	// The API view must never carry the sealed secret.
	view := storeBehaviorReportChannel(stored).Redacted()
	if view.EncryptedSecret != "" || view.Secret != "" || !view.HasSecret {
		t.Fatalf("secret leaked: %+v", view)
	}

	// Enqueue is idempotent on the key, so a replayed scan adds nothing.
	row := store.BehaviorReportOutboxRow{
		ReportID: "report-1", IdempotencyKey: behaviorreport.IdempotencyKey(behaviorreport.EventPoisonBehavior, "ev-1", "ncu-platform", "w1"),
		ChannelID: "ncu-platform", EventType: behaviorreport.EventPoisonBehavior, SubjectType: "ip", SubjectID: "10.155.9.9",
		AccountID: "student-1", IP: "10.155.9.9", Target: "w1", TargetType: "window", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := pg.EnqueueBehaviorReport(ctx, row); err != nil {
		t.Fatal(err)
	}
	duplicate := row
	duplicate.ReportID = "report-1-duplicate"
	if err := pg.EnqueueBehaviorReport(ctx, duplicate); err != nil {
		t.Fatal(err)
	}
	claimed, err := pg.ClaimBehaviorReportBatch(ctx, "ncu-platform", 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("idempotent enqueue must yield exactly one row: %+v %v", claimed, err)
	}
	if claimed[0].Attempts != 1 || claimed[0].Status != "sending" {
		t.Fatalf("claim must lease and count the attempt: %+v", claimed[0])
	}
	// A second claim finds nothing while the lease is held.
	if again, err := pg.ClaimBehaviorReportBatch(ctx, "ncu-platform", 10); err != nil || len(again) != 0 {
		t.Fatalf("leased row must not be claimed twice: %+v %v", again, err)
	}
	if err := pg.MarkBehaviorReportSent(ctx, claimed[0], 200, "remote-9"); err != nil {
		t.Fatal(err)
	}
	final, attempts, err := pg.GetBehaviorReportOutbox(ctx, "report-1")
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "sent" || final.RemoteID != "remote-9" || final.SentAt == "" || len(attempts) != 1 || attempts[0].Status != "sent" {
		t.Fatalf("sent state not recorded: %+v %+v", final, attempts)
	}

	// Retrying a failed report requeues it; cancelling a queued one stops it.
	retryRow := row
	retryRow.ReportID = "report-2"
	retryRow.IdempotencyKey = behaviorreport.IdempotencyKey(behaviorreport.EventProxyBehavior, "ev-2", "ncu-platform", "w2")
	retryRow.EventType = behaviorreport.EventProxyBehavior
	if err := pg.EnqueueBehaviorReport(ctx, retryRow); err != nil {
		t.Fatal(err)
	}
	if err := pg.RequeueBehaviorReport(ctx, "report-2"); err == nil {
		t.Fatal("a queued report must not be directly retryable")
	}
	if err := pg.CancelBehaviorReport(ctx, "report-2"); err != nil {
		t.Fatal(err)
	}
	cancelled, _, err := pg.GetBehaviorReportOutbox(ctx, "report-2")
	if err != nil || cancelled.Status != "cancelled" {
		t.Fatalf("cancel not applied: %+v %v", cancelled, err)
	}
	if err := pg.RequeueBehaviorReport(ctx, "report-2"); err != nil {
		t.Fatal(err)
	}
	requeued, _, err := pg.GetBehaviorReportOutbox(ctx, "report-2")
	if err != nil || requeued.Status != "queued" {
		t.Fatalf("retry not applied: %+v %v", requeued, err)
	}
}

func TestBehaviorReportWorkerDeliversAgainstRealStore(t *testing.T) {
	pg, ctx := requireOwnedBehaviorReportDatabase(t)
	server := &Server{actionMasterKey: []byte("behavior-report-integration-key")}
	sealed, err := server.encryptConnectorSecret("")
	if err != nil {
		t.Fatal(err)
	}
	var received int
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
		_, _ = w.Write([]byte(`{"id":"remote-worker"}`))
	}))
	defer platform.Close()
	channel := behaviorreport.Channel{
		ChannelID: "worker-platform", Name: "上报", EndpointURL: platform.URL, AuthType: behaviorreport.AuthNone,
		BatchSize: 10, TimeoutSeconds: 5, SuccessStatusCodes: []int{200},
		FieldMapping: map[string]string{"behavior_type": "event_type"}, Enabled: true,
	}
	if _, err := pg.UpsertBehaviorReportChannel(ctx, channel, sealed, "admin", true); err != nil {
		t.Fatal(err)
	}
	row := store.BehaviorReportOutboxRow{
		ReportID: "report-worker", IdempotencyKey: behaviorreport.IdempotencyKey(behaviorreport.EventAIRelayAudit, "ev-3", "worker-platform", "w3"),
		ChannelID: "worker-platform", EventType: behaviorreport.EventAIRelayAudit, SubjectType: "ip", SubjectID: "10.155.9.11",
		IP: "10.155.9.11", Target: "w3", TargetType: "window", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := pg.EnqueueBehaviorReport(ctx, row); err != nil {
		t.Fatal(err)
	}
	// Drive the worker's storage-facing steps directly: the PostgreSQL store
	// satisfies the reporting interface, which is a compile-time guarantee.
	worker := &Server{actionMasterKey: []byte("behavior-report-integration-key")}
	channels, err := pg.ListBehaviorReportChannels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	worker.enqueueBehaviorReportCandidates(ctx, pg, channels, time.Now().UTC())
	for _, item := range channels {
		if item.Enabled {
			worker.deliverBehaviorReportChannel(ctx, pg, item)
		}
	}
	if received != 1 {
		t.Fatalf("platform must receive exactly one batch, got %d", received)
	}
	final, _, err := pg.GetBehaviorReportOutbox(ctx, "report-worker")
	if err != nil || final.Status != "sent" || final.RemoteID != "remote-worker" {
		t.Fatalf("worker did not record delivery: %+v %v", final, err)
	}
}
