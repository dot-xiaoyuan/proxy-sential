package controlplane

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSRun4KCredentialsPostgresSave(t *testing.T) {
	s, actor := srunIsolatedReplayServer(t)
	s.actionMasterKey = []byte("isolated-test-encryption-key")
	s.operations.doc = emptyOperationsDocument()
	s.reader = configuredProbeAudit{db: s.operations.db}
	ctx := context.WithValue(context.Background(), sessionContextKey{}, actor)
	id := "credentials-" + shortToken(12)
	save := func(payload string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("PUT", "http://127.0.0.1:18090/api/v1/integrations/srun4k/"+id, strings.NewReader(payload)).WithContext(ctx)
		r.RemoteAddr = "127.0.0.1:31000"
		w := httptest.NewRecorder()
		s.saveSRun4K(w, r, id)
		if w.Code != 200 {
			t.Fatalf("save returned %d: %s", w.Code, w.Body.String())
		}
		return w
	}
	before := save(`{"host":"credentials-one.test","event_redis_host":"credentials-one.test"}`)
	if !strings.Contains(before.Body.String(), `"database_configured":false`) {
		t.Fatal("new integration should have no database credentials")
	}
	previous, err := s.loadSRun4K(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	w := save(`{"host":"credentials-one.test","credentials":{"database_username":"test-reader","database_password":"fixture-mysql","redis_password":"fixture-redis"}}`)
	if strings.Contains(w.Body.String(), "fixture-") || !strings.Contains(w.Body.String(), `"database_configured":true`) || !strings.Contains(w.Body.String(), `"redis_configured":true`) {
		t.Fatal("save response must contain status only")
	}
	saved, err := s.loadSRun4K(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if saved.storedCredentials.Revision == "" || saved.ConnectionState != "pending" {
		t.Fatal("new credentials must await a fresh test")
	}
	var raw string
	if err = s.operations.db.QueryRowContext(ctx, `SELECT setting_value::text FROM control_plane_settings WHERE setting_key=$1`, srun4KCredentialsPrefix+id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "fixture-mysql") || strings.Contains(raw, "fixture-redis") {
		t.Fatal("plaintext credential stored")
	}
	oldCheck := context.WithValue(ctx, srunOperationOrderKey{}, int64(10000))
	if result, err := s.completeSRun4KTest(oldCheck, previous, 81, time.Now(), true, false); err == nil || result != nil {
		t.Fatal("old test accepted after credential update")
	}
	save(`{"host":"credentials-one.test"}`)
	kept, err := s.loadSRun4K(ctx, id)
	if err != nil || kept.storedCredentials != saved.storedCredentials {
		t.Fatalf("blank update did not preserve saved configuration: %v", err)
	}
	save(`{"host":"credentials-two.test","event_redis_host":"credentials-two.test"}`)
	changed, err := s.loadSRun4K(ctx, id)
	if err != nil || changed.Credentials.DatabaseConfigured || changed.Credentials.RedisConfigured {
		t.Fatalf("changed hosts carried credentials: %v", err)
	}
}
