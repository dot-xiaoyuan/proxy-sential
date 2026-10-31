package controlplane

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPassiveClientSignalsKeepWeakIPAttributionAndConflicts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	mock.ExpectQuery("FROM unnest").WithArgs("192.0.2.8", "sensor-a").WillReturnRows(
		sqlmock.NewRows([]string{"sensor_id", "ip", "kind", "value", "last_seen", "event_id"}).
			AddRow("sensor-a", "192.0.2.8", "user_agent", "Mozilla/5.0 (Windows NT 10.0)", at, "http-1").
			AddRow("sensor-a", "192.0.2.8", "ja4", "ja4-fingerprint", at, "tls-1").
			AddRow("sensor-a", "192.0.2.8", "user_agent", "Mozilla/5.0 (Linux; Android 14)", at, "http-2"))
	items, err := readPassiveClientSignals(context.Background(), db, []string{"192.0.2.8"}, []string{"sensor-a"})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]*PassiveSignal{}
	for i := range items {
		mergePassiveSignal(byKey, &items[i])
	}
	merged := byKey["sensor-a|ip:192.0.2.8|"]
	if merged == nil || !merged.OSConflict || len(merged.ClientClues) != 3 || merged.ClientClues[1].Kind != "ja4" || merged.ClientClues[1].EvidenceID != "tls-1" || merged.OSConfidence != "weak" {
		t.Fatalf("IP-only client clues lost evidence or conflict: %+v", merged)
	}
	if passiveUserAgentOSFamily("generic browser") != "" || passiveUserAgentOSFamily("Mozilla/5.0 (Linux; Android 14)") != "Android" {
		t.Fatal("user-agent family parser invented an unsupported family")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
