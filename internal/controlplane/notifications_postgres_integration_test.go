package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/notify"
	"proxy-sentinel/internal/store"
)

// requireOwnedNotificationDatabase applies the migrations to an isolated test
// database. Delivery is stateful and retry-based, so a fake database would not
// exercise the behaviour under test.
func requireOwnedNotificationDatabase(t *testing.T) (*Server, context.Context) {
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
	o, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.db.Close() })
	// These acceptance tests share one database with the rest of the suite, so
	// they must be re-runnable: clear only their own rows.
	if _, err := o.db.ExecContext(ctx, `DELETE FROM notification_delivery_attempts; DELETE FROM notification_outbox; DELETE FROM notification_channels; DELETE FROM notification_templates;`); err != nil {
		t.Fatal(err)
	}
	return &Server{operations: o, notifications: newNotificationManager(o.db), actionMasterKey: []byte("notification-test-master-key")}, ctx
}

func TestNotificationChannelSecretIsNeverReadableAndSupportsDefault(t *testing.T) {
	s, ctx := requireOwnedNotificationDatabase(t)
	m := s.notifications
	sealed, err := s.encryptConnectorSecret("super-secret")
	if err != nil {
		t.Fatal(err)
	}
	channel := notify.Channel{ChannelID: "primary", Name: "值班通道", ChannelType: notify.ChannelTypeHTTP, EndpointURL: "https://example.invalid/hook", AuthType: notify.AuthBearer, Enabled: true, IsDefault: true}
	if _, err := m.upsertChannel(ctx, channel, sealed, "admin", true); err != nil {
		t.Fatal(err)
	}
	stored, err := m.getChannel(ctx, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if stored.EncryptedSecret != sealed {
		t.Fatal("sealed secret not persisted")
	}
	redacted := stored.Redacted()
	if redacted.EncryptedSecret != "" || redacted.Secret != "" || !redacted.HasSecret {
		t.Fatalf("secret leaked through the API view: %+v", redacted)
	}
	resolved, err := s.resolveNotificationChannel(ctx, m, "")
	if err != nil || resolved.ChannelID != "primary" {
		t.Fatalf("default channel not resolved: %+v %v", resolved, err)
	}
	// Disabling the only default channel must stop implicit resolution.
	channel.Enabled = false
	channel.Revision = stored.Revision
	if _, err := m.upsertChannel(ctx, channel, sealed, "admin", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveNotificationChannel(ctx, m, ""); err == nil {
		t.Fatal("disabled channel must not resolve as default")
	}
}

func TestNotificationOutboxDeliversRetriesAndNeverSilentlyQueues(t *testing.T) {
	s, ctx := requireOwnedNotificationDatabase(t)
	m := s.notifications
	var received int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
		if received == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"messageId":"remote-7"}`))
	}))
	defer server.Close()
	sealed, err := s.encryptConnectorSecret("token")
	if err != nil {
		t.Fatal(err)
	}
	channel := notify.Channel{ChannelID: "webhook", Name: "值班 Webhook", ChannelType: notify.ChannelTypeHTTP, EndpointURL: server.URL, AuthType: notify.AuthBearer, Enabled: true}
	if _, err := m.upsertChannel(ctx, channel, sealed, "admin", true); err != nil {
		t.Fatal(err)
	}
	template := notify.Template{TemplateID: "reminder", Name: "提醒", Body: "账号 {{account}} 触发 {{policy_name}}", Enabled: true}
	if _, err := m.upsertTemplate(ctx, template, "admin", true); err != nil {
		t.Fatal(err)
	}
	if err := m.enqueue(ctx, "notification-1", "idem-1", "student-1", "reminder", map[string]string{"account": "student-1", "policy_name": "防代理策略"}, "webhook"); err != nil {
		t.Fatal(err)
	}
	// First attempt fails transiently and must return to the queue with an attempt record.
	row, found, err := m.claimDue(ctx)
	if err != nil || !found {
		t.Fatalf("claim: %+v %v %v", row, found, err)
	}
	if row.Attempts != 1 {
		t.Fatalf("attempts must increment at claim time: %d", row.Attempts)
	}
	s.deliverNotification(ctx, row)
	stored, attempts, err := m.getOutbox(ctx, "notification-1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "queued" || len(attempts) != 1 || attempts[0].Status != "failed" {
		t.Fatalf("transient failure must requeue with a recorded attempt: %+v %+v", stored, attempts)
	}
	// Make the retry immediately due instead of waiting for the backoff.
	if _, err := m.db.ExecContext(ctx, `UPDATE notification_outbox SET next_attempt_at=now() WHERE notification_id='notification-1'`); err != nil {
		t.Fatal(err)
	}
	row, found, err = m.claimDue(ctx)
	if err != nil || !found {
		t.Fatalf("second claim: %+v %v", row, err)
	}
	s.deliverNotification(ctx, row)
	stored, attempts, err = m.getOutbox(ctx, "notification-1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "sent" || stored.RemoteID != "remote-7" || stored.SentAt == "" || len(attempts) != 2 {
		t.Fatalf("delivery not recorded: %+v %+v", stored, attempts)
	}
	var rendered map[string]any
	if err := json.Unmarshal([]byte(mustRenderedPayload(t, ctx, m)), &rendered); err != nil {
		t.Fatal(err)
	}
	if rendered["body"] != "账号 student-1 触发 防代理策略" {
		t.Fatalf("template not rendered: %+v", rendered)
	}
	// A notification with no channel anywhere must fail loudly, not stay queued.
	if _, err := m.db.ExecContext(ctx, `UPDATE notification_channels SET enabled=false,is_default=false`); err != nil {
		t.Fatal(err)
	}
	if err := m.failUnroutable(ctx, "notification-2", "idem-2", "student-2", "reminder", map[string]string{"account": "student-2"}, "未配置通知通道"); err != nil {
		t.Fatal(err)
	}
	unroutable, _, err := m.getOutbox(ctx, "notification-2")
	if err != nil {
		t.Fatal(err)
	}
	if unroutable.Status != "failed" {
		t.Fatalf("unroutable notification must not stay queued: %+v", unroutable)
	}
}

func mustRenderedPayload(t *testing.T, ctx context.Context, m *notificationManager) string {
	t.Helper()
	var raw []byte
	if err := m.db.QueryRowContext(ctx, `SELECT rendered_payload FROM notification_outbox WHERE notification_id='notification-1'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestNotificationOutboxRetryAndCancelGuards(t *testing.T) {
	s, ctx := requireOwnedNotificationDatabase(t)
	m := s.notifications
	if err := m.enqueue(ctx, "notification-3", "idem-3", "student-3", "literal body", map[string]string{}, ""); err != nil {
		t.Fatal(err)
	}
	// A queued notification can be cancelled but not retried.
	if err := m.requeue(ctx, "notification-3"); err == nil {
		t.Fatal("queued notification must not be retryable")
	}
	if err := m.cancel(ctx, "notification-3"); err != nil {
		t.Fatal(err)
	}
	row, _, err := m.getOutbox(ctx, "notification-3")
	if err != nil || row.Status != "cancelled" {
		t.Fatalf("cancel not applied: %+v %v", row, err)
	}
	if err := m.requeue(ctx, "notification-3"); err != nil {
		t.Fatal(err)
	}
	row, _, err = m.getOutbox(ctx, "notification-3")
	if err != nil || row.Status != "queued" {
		t.Fatalf("retry not applied: %+v %v", row, err)
	}
}
