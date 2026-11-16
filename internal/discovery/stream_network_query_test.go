package discovery

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

type streamNetworkQueryMatcher struct{}

func (streamNetworkQueryMatcher) Match(expected, actual string) error {
	if expected == "network-history-page" {
		for _, required := range []string{"FROM stream_discovery_network_state n", "n.status='expired' OR (n.status='clue' AND n.type_valid_until<=now())", "'pending_expiry'", "newer.result_version>s.result_version"} {
			if !strings.Contains(actual, required) {
				return fmt.Errorf("network history lacks %s", required)
			}
		}
		if strings.Contains(actual, "s.document->>'current'='true'") {
			return fmt.Errorf("historical clue incorrectly requires current device")
		}
		return nil
	}
	if expected != "network-page" {
		return sqlmock.QueryMatcherRegexp.Match(expected, actual)
	}
	for _, required := range []string{"FROM stream_discovery_network_state n", "JOIN stream_discovery_device_state s", "n.type_valid_until>now()", "n.network_device_type IN ('router','gateway')", "newer.result_version>s.result_version", "LIMIT"} {
		if !strings.Contains(actual, required) {
			return fmt.Errorf("network page lacks %s", required)
		}
	}
	for _, forbidden := range []string{"s.last_device_type=", "count(*) OVER()", "discovery_device_current_shadow"} {
		if strings.Contains(actual, forbidden) {
			return fmt.Errorf("network page includes %s", forbidden)
		}
	}
	return nil
}

func TestStreamExpiredNetworkClueIncludesPendingExpiryWithoutCurrentDevice(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(streamNetworkQueryMatcher{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("network-history-page").WillReturnRows(sqlmock.NewRows([]string{"device_key", "type_last_seen", "result_version", "document"}).
		AddRow("network-expired", now.Add(-time.Minute), int64(11), []byte(`{"id":"network-expired","current":false,"last_network_device_type":"router","network_type_status":"pending_expiry"}`)))
	mock.ExpectQuery("SELECT min\\(p.accepted_at\\)").WillReturnRows(sqlmock.NewRows([]string{"accepted", "projected", "processing_lag", "version", "active", "projected_epochs"}).AddRow(now.Add(-time.Minute), now, float64(60), int64(11), 1, 1))
	mock.ExpectQuery("JOIN stream_discovery_network_backfill_progress p").WillReturnRows(sqlmock.NewRows([]string{"covered"}).AddRow(false))
	page, err := (Repository{DB: db, ActiveStreamOnly: true}).DevicesState(context.Background(), DeviceQuery{Mode: "passive", DeviceType: "router", State: "expired", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]map[string]any)
	if len(items) != 1 || items[0]["network_type_status"] != "pending_expiry" || items[0]["current"] != false {
		t.Fatalf("pending expiry was treated as current: %+v", page)
	}
}

func TestStreamPassiveRouterPageUsesSparseTypeProjection(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(streamNetworkQueryMatcher{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("network-page").WillReturnRows(sqlmock.NewRows([]string{"device_key", "type_last_seen", "result_version", "document"}).
		AddRow("network-1", now, int64(10), []byte(`{"id":"network-1","current":true,"network_device_type":"gateway","network_type_status":"clue","network_type_reason":"被动公告类型线索"}`)))
	mock.ExpectQuery("SELECT min\\(p.accepted_at\\)").WillReturnRows(sqlmock.NewRows([]string{"accepted", "projected", "processing_lag", "version", "active", "projected_epochs"}).AddRow(now, now, float64(0), int64(10), 1, 1))
	mock.ExpectQuery("JOIN stream_discovery_network_backfill_progress p").WillReturnRows(sqlmock.NewRows([]string{"covered"}).AddRow(false))
	page, err := (Repository{DB: db, ActiveStreamOnly: true}).DevicesState(context.Background(), DeviceQuery{Mode: "passive", DeviceType: "router", Window: 24 * time.Hour, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]map[string]any)
	if len(items) != 1 || items[0]["network_device_type"] != "gateway" || page["network_type_coverage"] != "new_observations" {
		t.Fatalf("network clue not returned with coverage: %+v", page)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamNetworkPageReportsCompletedHistoricalCoverage(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(streamNetworkQueryMatcher{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("network-page").WillReturnRows(sqlmock.NewRows([]string{"device_key", "type_last_seen", "result_version", "document"}))
	mock.ExpectQuery("SELECT min\\(p.accepted_at\\)").WillReturnRows(sqlmock.NewRows([]string{"accepted", "projected", "processing_lag", "version", "active", "projected_epochs"}).AddRow(now, now, float64(0), int64(10), 1, 1))
	mock.ExpectQuery("JOIN stream_discovery_network_backfill_progress p").WillReturnRows(sqlmock.NewRows([]string{"covered"}).AddRow(true))
	page, err := (Repository{DB: db, ActiveStreamOnly: true}).DevicesState(context.Background(), DeviceQuery{Mode: "passive", DeviceType: "router", Limit: 20})
	if err != nil || page["network_type_coverage"] != "complete" {
		t.Fatalf("completed retained-history backfill was not reported: %+v %v", page, err)
	}
}
