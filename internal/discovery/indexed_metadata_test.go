package discovery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIndexedSelectionLimitsHistoricalLinkLookup(t *testing.T) {
	selection, err := buildIndexedDeviceSelection(DeviceQuery{Mode: "passive"})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"link_exceptions AS MATERIALIZED",
		"LEFT JOIN link_exceptions ix ON ix.observation_id=l.id",
		"LEFT JOIN LATERAL (",
		"coalesce(l.data->>'mac','')=''",
		"coalesce(basis->>'mac','')='' OR lower(endpoint_id)<>'mac:'||lower(basis->>'mac')",
		"FROM display_links) active ON active.endpoint_id=rec.endpoint_id",
	} {
		if !strings.Contains(selection.CTE, fragment) {
			t.Fatalf("current selection still scans historical links: missing %q", fragment)
		}
	}
}

func TestIndexedMetadataCountsFilteredTrustedIdentitiesWithoutPagination(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	mock.ExpectQuery(`(?s)identity_key.*GROUP BY identity_key.*matched.*classification_status.*GROUP BY classification_status`).WillReturnRows(sqlmock.NewRows([]string{"status", "type", "count", "as_of"}).AddRow("identified", "access_point", 5, at).AddRow("candidate", "access_point", 2, at).AddRow("conflict", "", 1, at).AddRow("expired", "", 1, at))
	mock.ExpectQuery(`FROM passive_discovery_state`).WillReturnRows(sqlmock.NewRows([]string{"cursor_timestamp", "last_success_at", "last_error", "updated_at"}).AddRow(at, at, "", at))
	metadata, err := (Repository{DB: db}).DevicesIndexedMetadata(context.Background(), DeviceQuery{Mode: "passive", DeviceType: "access_point", State: "identified", Cursor: "ignored", Offset: 99, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Total != 9 || metadata.Identified != 5 || metadata.Candidate != 2 || metadata.Conflict != 1 || metadata.Expired != 1 || len(metadata.Types) != 1 || metadata.Types[0].DeviceType != "access_point" || metadata.Types[0].Count != 5 || metadata.CountUnit != "trusted_discovery_identity" || !metadata.AsOf.Equal(at) {
		t.Fatalf("metadata=%+v", metadata)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIndexedMetadataPropagatesQueryFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("GROUP BY classification_status").WillReturnError(context.DeadlineExceeded)
	if _, err = (Repository{DB: db}).DevicesIndexedMetadata(context.Background(), DeviceQuery{}); err == nil {
		t.Fatal("failed statistics became empty success")
	}
}

func TestHardwareMetadataReportsCandidatesApartFromConfirmedTypes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	mock.ExpectQuery("(?s)endpoint_recognition_summary.*GROUP BY classification_status").
		WillReturnRows(sqlmock.NewRows([]string{"status", "type", "count", "as_of"}).
			AddRow("identified", "printer", 3, at).
			AddRow("profile_typed", "mobile", 12, at).
			AddRow("ip_product_only", "", 2, at).
			AddRow("no_type_clue", "", 3, at).
			AddRow("revoked", "", 1, at))
	metadata, err := (Repository{HardwareV2: true}).devicesIndexedMetadata(context.Background(), db, DeviceQuery{Mode: "passive"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Total != 21 || metadata.Identified != 3 || metadata.Candidate != 17 ||
		metadata.ProfileTyped != 12 || metadata.IPProductOnly != 2 || metadata.NoTypeClue != 3 || metadata.Revoked != 1 || metadata.Expired != 1 ||
		len(metadata.Types) != 1 || metadata.Types[0] != (IndexedDeviceTypeCount{DeviceType: "printer", Count: 3}) ||
		len(metadata.CandidateTypes) != 1 || metadata.CandidateTypes[0] != (IndexedDeviceTypeCount{DeviceType: "mobile", Count: 12}) {
		t.Fatalf("metadata=%+v", metadata)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIndexedIdentityAggregationPreservesStableGroupAndHistoryKey(t *testing.T) {
	now := time.Now().UTC()
	first := deviceObservationRow{DeviceKey: "history-a", IndexedIdentityKey: "scope-mac", Observation: Observation{ID: "a", MAC: "00:11:22:33:44:55", IP: "10.0.0.8", Origin: "arp", ObservedAt: now, ValidUntil: now.Add(time.Hour)}}
	second := first
	second.Observation.ID = "b"
	second.Observation.IP = "fe80::8"
	second.EndpointID = "mac:00:11:22:33:44:55"
	other := first
	other.IndexedIdentityKey = "other-scope-mac"
	other.Observation.ID = "c"
	other.Observation.MAC = "00:11:22:33:44:56"
	items, err := aggregateIndexedDeviceRows([]deviceObservationRow{first, second, other}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("trusted identity groups changed: %d", len(items))
	}
	seen := map[string]bool{}
	for _, item := range items {
		if item.ID != "history-a" {
			t.Fatal("history key changed")
		}
		seen[item.indexedIdentityKey] = true
	}
	if len(seen) != 2 {
		t.Fatal("distinct groups lost stable cursor identity")
	}
}

func TestIndexedCursorUsesIdentityForEqualHistoryKeys(t *testing.T) {
	q := DeviceQuery{Mode: "passive", Window: 24 * time.Hour}
	now := time.Now().UTC()
	a, err := encodeIndexedDeviceCursor(q, DeviceView{ID: "same-history", LastSeen: now, indexedIdentityKey: "identity-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := encodeIndexedDeviceCursor(q, DeviceView{ID: "same-history", LastSeen: now, indexedIdentityKey: "identity-b"})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("identity cursor aliases distinct rows")
	}
	q.Cursor = b
	c, err := decodeIndexedDeviceCursor(q)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 2 || c.IdentityKey != "identity-b" {
		t.Fatalf("cursor=%+v", c)
	}
}

func TestIndexedPageReturnsExactlySQLIdentityGroups(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"identity_key", "device_key", "data", "endpoint_id", "role", "confidence", "conflict", "category"})
	for _, identity := range []string{"first", "second"} {
		raw, _ := json.Marshal(Observation{ID: identity, Origin: "arp", MAC: "00:11:22:33:44:55", ObservedAt: now, ValidUntil: now.Add(time.Hour)})
		rows.AddRow(identity, "same-history", raw, "", "access_point", .95, false, "network")
	}
	mock.ExpectQuery(`(?s)GROUP BY identity_key.*ORDER BY last_seen DESC,identity_key.*LIMIT`).WillReturnRows(rows)
	page, err := (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page["items"].([]DeviceView)) != 1 || page["has_more"] != true {
		t.Fatalf("page=%+v", page)
	}
}

func TestIndexedWindowIsBoundedAndSharedWithMetadata(t *testing.T) {
	for _, tc := range []struct{ window, want time.Duration }{{0, 24 * time.Hour}, {-1, 720 * time.Hour}, {800 * time.Hour, 720 * time.Hour}, {48 * time.Hour, 48 * time.Hour}} {
		selection, err := buildIndexedDeviceSelection(DeviceQuery{Window: tc.window})
		if err != nil {
			t.Fatal(err)
		}
		if selection.Query.Window != tc.want {
			t.Fatalf("window=%s effective=%s want=%s", tc.window, selection.Query.Window, tc.want)
		}
	}
}

func TestHardwareMetadataReportsVLANFacetWithoutCountingItAsDevices(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	mock.ExpectQuery(`(?s)GROUP BY classification_status.*UNION ALL SELECT 'vlan',vlan,n,now\(\) FROM \(SELECT vlan,count\(\*\) n FROM matched WHERE vlan<>'' GROUP BY vlan ORDER BY count\(\*\) DESC,vlan LIMIT 100\) v`).
		WillReturnRows(sqlmock.NewRows([]string{"status", "type", "count", "as_of"}).
			AddRow("identified", "printer", 3, at).
			AddRow("vlan", "201", 4, at).
			AddRow("vlan", "101", 12, at).
			AddRow("vlan", "102", 4, at))
	metadata, err := (Repository{HardwareV2: true}).devicesIndexedMetadata(context.Background(), db, DeviceQuery{Mode: "passive"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Total != 3 || metadata.Identified != 3 {
		t.Fatalf("vlan rows must not change device totals: %+v", metadata)
	}
	want := []IndexedVLANCount{{VLAN: "101", Count: 12}, {VLAN: "102", Count: 4}, {VLAN: "201", Count: 4}}
	if len(metadata.VLANs) != len(want) {
		t.Fatalf("vlans=%+v", metadata.VLANs)
	}
	for i := range want {
		if metadata.VLANs[i] != want[i] {
			t.Fatalf("vlan %d=%+v want %+v", i, metadata.VLANs[i], want[i])
		}
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHardwareSelectionCarriesVLANIntoIdentityGroups(t *testing.T) {
	selection, err := buildIndexedDeviceSelection(DeviceQuery{Mode: "passive", HardwareV2: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"max(vlan) vlan", "identity_key,l.vlan,l.observation_capabilities", "l.identity_key,l.vlan,l.observation_capabilities"} {
		if !strings.Contains(selection.CTE, fragment) {
			t.Fatalf("hardware selection does not expose vlan for the facet: missing %q", fragment)
		}
	}
}
