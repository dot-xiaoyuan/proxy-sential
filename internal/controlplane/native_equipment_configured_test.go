package controlplane

import (
	"context"
	"database/sql"
	"os"
	"proxy-sentinel/internal/srunapi"
	"sort"
	"testing"
	"time"
)

// Explicit onsite read-only acceptance. No configuration or business writes,
// no controller request, no secrets or other accounts in the output.
func TestConfigured190EquipmentReadOnly(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_CONFIGURED_PROBE") != "190-equipment-read-only" {
		t.Skip("explicit onsite read-only acceptance required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil {
		t.Fatal("storage unavailable")
	}
	defer db.Close()
	doc := emptyOperationsDocument()
	if loadConnectorsScoped(ctx, db, &doc, " WHERE connector_type='srun4k' AND endpoint_url='https://192.168.0.190:8001'", nil) != nil || len(doc.Connectors) != 1 {
		t.Fatal("exactly one configured connector required")
	}
	var connector ActionConnector
	for _, item := range doc.Connectors {
		connector = item
	}
	if connector.Mode != "shadow" || connector.CertificatePEM == "" {
		t.Fatal("shadow and verified certificate required")
	}
	s := &Server{operations: &operationsState{db: db}, actionMasterKey: []byte(os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY"))}
	creds, err := s.credentialsFrom4K(ctx, connector.ConnectorID)
	if err != nil {
		t.Fatal("authorization unavailable")
	}
	hc, err := srunapi.NewCertificatePinnedClient([]byte(connector.CertificatePEM))
	if err != nil {
		t.Fatal("certificate unavailable")
	}
	defer hc.CloseIdleConnections()
	client, err := srunapi.New(connector.EndpointURL, creds.AppID, creds.AppSecret, hc)
	if err != nil {
		t.Fatal("API configuration invalid")
	}
	observed, err := client.OnlineEquipment(ctx, "yuantong")

	t.Logf("target=yuantong rows=%d complete=%t absence_verified=%t blocker=%s", len(observed.Rows), observed.Complete, observed.AbsenceVerified, observed.Blocker)
	for _, row := range observed.Rows {
		if row["user_name"] != "yuantong" {
			continue
		}
		keys := []string{}
		for key := range row {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		t.Logf("target account=%s ip=%s raw_online_id=%s login_generation=%s fields=%v", row["user_name"], row["ip"], row["rad_online_id"], row["add_time"], keys)
	}
	if err != nil {
		t.Fatalf("read-only account query: %v", err)
	}
	capability, err := client.InspectEquipmentCapabilities(ctx)
	if err != nil {
		t.Logf("unfiltered inventory query unavailable: %v; enforcement remains blocked", err)
	} else {
		t.Logf("unfiltered query shape=%s rows=%d field_names=%v complete=%t blocker=%s", capability.Shape, capability.RecordCount, capability.Fields, capability.Complete, capability.Blocker)
	}
	dataCapability, dataErr := client.InspectOnlineDataCapabilities(ctx)
	if dataErr != nil {
		t.Logf("online-data read-only capability unavailable: %v; complete identity remains blocked", dataErr)
	} else {
		t.Logf("online-data shape=%s rows=%d fields=%v complete=%t blocker=%s", dataCapability.Shape, dataCapability.RecordCount, dataCapability.Fields, dataCapability.Complete, dataCapability.Blocker)
	}

}
