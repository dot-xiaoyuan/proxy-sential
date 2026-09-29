package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/store"
	"strings"
	"testing"
	"time"
)

type configuredProbeAudit struct {
	store.Reader
	db *sql.DB
}

func (a configuredProbeAudit) AppendAuditLog(ctx context.Context, entry store.AuditLog) error {
	_, err := a.db.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,$3,$4,$5,$6::timestamptz)`, entry.AuditID, entry.Actor, entry.Action, entry.Target, entry.Outcome, entry.CreatedAt)
	return err
}

// Opt-in acceptance on the Sentinel host. Never connects to 190 by SSH, sends
// controls or modifies business records. The sole write provisions the already
// verified certificate through the normal connector mutation and audit path.
func TestConfigured190CertificateAndReadOnlyProbe(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_CONFIGURED_PROBE") != "190-certificate-and-read-only" {
		t.Skip("explicit configured acceptance required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dsn := os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")
	key := os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY")
	if dsn == "" || key == "" {
		t.Fatal("Sentinel configuration unavailable")
	}
	cert, err := os.ReadFile(os.Getenv("PROXY_SENTINEL_VERIFIED_CERTIFICATE"))
	if err != nil {
		t.Fatal("verified certificate unavailable")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("configuration storage unavailable")
	}
	defer db.Close()
	doc := emptyOperationsDocument()
	if err = loadConnectorsScoped(ctx, db, &doc, " WHERE connector_type='srun4k' AND endpoint_url='https://192.168.0.190:8001'", nil); err != nil || len(doc.Connectors) != 1 {
		t.Fatal("exactly one configured190 connector required")
	}
	var connector ActionConnector
	for _, item := range doc.Connectors {
		connector = item
	}
	if connector.Mode != "shadow" {
		t.Fatal("only shadow configuration accepted")
	}
	if connector.CertificatePEM != "" && strings.TrimSpace(connector.CertificatePEM) != strings.TrimSpace(string(cert)) {
		t.Fatal("existing certificate differs; refusing overwrite")
	}
	s := &Server{operations: &operationsState{db: db}, actionMasterKey: []byte(key), reader: configuredProbeAudit{db: db}}
	certificate := string(cert)
	raw, _ := json.Marshal(connectorRequest{ConnectorID: connector.ConnectorID, ConnectorType: connector.ConnectorType, Name: connector.Name, EndpointURL: connector.EndpointURL, Mode: connector.Mode, Enabled: connector.Enabled, ActionMapping: connector.ActionMapping, CertificatePEM: &certificate})
	req := httptest.NewRequest("POST", "/api/v1/actions/connectors", strings.NewReader(string(raw)))
	req = req.WithContext(context.WithValue(ctx, sessionContextKey{}, Session{User: User{ID: "codex-authorized-certificate-setup"}, Role: "admin", Permissions: rolePermissions("admin")}))
	w := httptest.NewRecorder()
	s.handleActions(w, req)
	if w.Code != 200 {
		t.Fatalf("certificate save rejected: %d", w.Code)
	}
	var saved ActionConnector
	if err = json.Unmarshal(w.Body.Bytes(), &saved); err != nil || saved.CertificatePEM == "" {
		t.Fatal("certificate persistence invalid")
	}
	count, err := s.probeManaged4K(ctx, saved, nil)
	if err != nil {
		t.Fatalf("read-only management probe: %v", err)
	}
	t.Logf("configured190 certificate persisted; token and read-only online total succeeded; online_total=%d; identity_verified=false; enforcement_ready=false", count)
}
