package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRouterAssetListReadsMaintainedStreamWithEventBusShadowEnabled(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_DISCOVERY_V2", "")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ", "true")
	for _, readSource := range []struct{ name, global, router string }{
		{name: "184-global-stream", global: "stream"},
		{name: "router-only-stream", router: "stream"},
	} {
		for _, deviceType := range []string{"router", "access_point"} {
			t.Run(readSource.name+"/"+deviceType, func(t *testing.T) {
				t.Setenv("PROXY_SENTINEL_DISCOVERY_CURRENT_SOURCE", readSource.global)
				t.Setenv("PROXY_SENTINEL_ROUTER_ASSET_CURRENT_SOURCE", readSource.router)
				db, mock, err := sqlmock.New()
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				now := time.Now().UTC()
				mock.ExpectQuery(`WITH fresh AS MATERIALIZED`).WillReturnRows(sqlmock.NewRows([]string{"device_key", "last_seen", "result_version", "document"}).AddRow("stream-device", now, int64(42), []byte(`{"id":"stream-device","current":true,"device_type":"`+deviceType+`"}`)))
				mock.ExpectQuery(`SELECT min\(p.accepted_at\),min\(p.projected_at\)`).WillReturnRows(sqlmock.NewRows([]string{"accepted", "projected", "processing_lag", "version", "active", "projected_epochs"}).AddRow(now.Add(-2*time.Second), now, 2.0, int64(42), 1, 1))
				server := &Server{operations: &operationsState{db: db}}
				response := httptest.NewRecorder()
				server.handleDiscovery(response, httptest.NewRequest("GET", "/discovery/devices?mode=passive&type="+deviceType+"&window=24h", nil), "/discovery/devices")
				if response.Code != 200 {
					t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
				var result struct {
					Items     []map[string]any `json:"items"`
					Freshness map[string]any   `json:"freshness"`
					Total     *int             `json:"total"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Items) != 1 || result.Freshness["source"] != "stream" || result.Total != nil {
					t.Fatalf("router asset page=%+v", result)
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
