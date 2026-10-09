package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/redis/go-redis/v9"
	"os"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/store"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func snapshotConversionFixture(records int) identitySnapshotRequest {
	at := time.Date(2026, 10, 1, 3, 0, 0, 123000, time.UTC)
	rows := make([]map[string]string, records)
	for i := range rows {
		id := strconv.Itoa(i/2 + 1)
		ip := "192.0.2.1"
		if i%2 == 1 {
			ip = "2001:db8::1"
		}
		rows[i] = map[string]string{"account_id": "测试账号", "ip": ip, "session_id": legacy4k.OnlineSessionID("fixed-run", id, "1790820000"), "source_session_id": id, "raw_online_id": id, "source_login_generation": "1790820000", "session_id_source": "derived_source_session_login", "mac": "02:00:00:00:00:01", "nas_ip": "192.0.2.254", "endpoint_id": "endpoint-1", "group_id": "1", "product_id": "1", "source_instance_id": "fixed-run", "vlan": "7", "control_id": "control-1"}
	}
	return identitySnapshotRequest{IdentityScope: store.IdentityScope{Source: "srun4k:conversion-replay", SensorID: "srun4k-direct:conversion-replay"}, ObservedAt: at, IntervalSeconds: 21600, Complete: true, ExpectedCount: &records, Records: rows}
}
func TestSnapshotConversionFrozenR65Events(t *testing.T) {
	request := snapshotConversionFixture(4)
	request.Records[0]["department"] = "院系 <A&B>\n楼层"
	request.Records[0]["identity_confidence"] = "0.73"
	request.Records[1]["mac"] = "AABB.CCDD.EEFF"
	request.Records[2]["ip"] = "::ffff:192.0.2.2"
	request.Records[2]["endpoint_id"] = ""
	request.Records[2]["ignored_note"] = "影响事件 ID 的原始字段"
	now := request.ObservedAt.Add(time.Minute)
	got, err := prepareIdentitySnapshotWithLimit(request, "frozen-r65", now, legacy4k.MaxIdentityAddressRecords)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := "testdata/identity-conversion-r65.json"
	frozen, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), bytes.TrimSpace(frozen)) {
		t.Fatal("normalized events or stable IDs differ from frozen r65 output")
	}
}
func BenchmarkPrepareIdentitySnapshot(b *testing.B) {
	request := snapshotConversionFixture(2000)
	now := request.ObservedAt.Add(time.Minute)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := prepareIdentitySnapshotWithLimit(request, "benchmark", now, legacy4k.MaxIdentityAddressRecords); err != nil {
			b.Fatal(err)
		}
	}
}
func TestSnapshotConversionNativeMaximum(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_CONVERSION_MAXIMUM") != "1" {
		t.Skip("explicit isolated large conversion acceptance required")
	}
	request := snapshotConversionFixture(legacy4k.MaxIdentityAddressRecords)
	now := request.ObservedAt.Add(time.Minute)
	started := time.Now()
	snapshot, err := prepareIdentitySnapshotWithLimit(request, "maximum", now, legacy4k.MaxIdentityAddressRecords)
	if err != nil || len(snapshot.Events) != legacy4k.MaxIdentityAddressRecords {
		t.Fatalf("maximum rejected: events=%d err=%v", len(snapshot.Events), err)
	}
	for i, event := range snapshot.Events {
		if event.EventID == "" || event.Payload["session_id"] != request.Records[i]["session_id"] || event.Subject["ip"] != request.Records[i]["ip"] || event.Payload["reconcile_interval_seconds"] != "21600" || event.RawRef["snapshot_id"] != "maximum" {
			t.Fatalf("record %d lost identity or scope", i)
		}
	}
	t.Logf("200000 identity events converted and validated in %s", time.Since(started))
}

func TestSnapshotConversionMatchesJSONReference(t *testing.T) {
	for _, name := range []string{"managed", "scoped", "invalid_utf8_fields", "invalid_utf8_authority", "nan_last", "positive_inf", "negative_inf", "invalid_last_scope", "invalid_last_ip", "mapped_duplicate", "empty", "nil_inventory", "oversized_escaped_record"} {
		t.Run(name, func(t *testing.T) {
			request := snapshotConversionFixture(4)
			switch name {
			case "scoped":
				request.Source = "radius"
				request.SensorID = "传感器-甲"
				request.CampusID = "东校区"
				request.AccessDomain = "宿舍 Wi-Fi"
				request.IntervalSeconds = 60
			case "invalid_utf8_fields":
				request.Records[0]["account_id"] = "a\xff\xfe"
				request.Records[0]["ignored_\xff"] = "last"
				request.Records[0]["ignored_\xfe"] = "first"
				request.Records[0]["department"] = "\xff\xff\xe2\x80\xa8&<>\n"
			case "invalid_utf8_authority":
				request.Source = "srun4k:\xff"
				request.SensorID = "sensor-\xfe"
				request.CampusID = "campus-\xff"
				request.AccessDomain = "domain-\xfe"
			case "nan_last":
				request.Records[3]["identity_confidence"] = "NaN"
			case "positive_inf":
				request.Records[3]["identity_confidence"] = "+Inf"
			case "negative_inf":
				request.Records[3]["identity_confidence"] = "-Inf"
			case "invalid_last_scope":
				request.Records[3]["source"] = "other"
			case "invalid_last_ip":
				request.Records[3]["ip"] = "invalid"
			case "mapped_duplicate":
				request.Records[1]["ip"] = "::ffff:192.0.2.1"
			case "empty":
				request.Records = []map[string]string{}
				count := 0
				request.ExpectedCount = &count
			case "nil_inventory":
				request.Records = nil
				count := 0
				request.ExpectedCount = &count
			case "oversized_escaped_record":
				request.Records[3]["ignored_note"] = strings.Repeat("&", (16<<20)/6+1)
			}
			before, _ := json.Marshal(request)
			now := request.ObservedAt.Add(time.Minute)
			expected, expectedErr := prepareIdentitySnapshotJSONReference(request, "differential", now, legacy4k.MaxIdentityAddressRecords)
			got, err := prepareIdentitySnapshotWithLimit(request, "differential", now, legacy4k.MaxIdentityAddressRecords)
			if (err == nil) != (expectedErr == nil) {
				t.Fatalf("acceptance changed: current=%v reference=%v", err, expectedErr)
			}
			if !reflect.DeepEqual(got, expected) {
				t.Fatalf("snapshot differs for %s: current events=%d reference events=%d", name, len(got.Events), len(expected.Events))
			}
			after, _ := json.Marshal(request)
			if !bytes.Equal(before, after) {
				t.Fatal("input maps mutated")
			}
		})
	}
}

func TestSnapshotConversionDoesNotAllocateJSONRoundTrips(t *testing.T) {
	request := snapshotConversionFixture(100)
	now := request.ObservedAt.Add(time.Minute)
	var count int
	allocations := testing.AllocsPerRun(1, func() {
		snapshot, err := prepareIdentitySnapshotWithLimit(request, "allocation", now, legacy4k.MaxIdentityAddressRecords)
		if err != nil {
			panic(err)
		}
		count = len(snapshot.Events)
	})
	if count != 100 {
		t.Fatalf("partial snapshot: %d", count)
	}
	if allocations > 25000 {
		t.Fatalf("complete snapshot allocated JSON round-trip copies: %.0f allocations", allocations)
	}
}

// This preview only reads the explicitly configured controller's identity Redis.
// It never calls network probes, reconciliation storage or enforcement actions.
func TestSnapshotConversionConfiguredReadOnlyPreview(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_CONVERSION_UPSTREAM") != "1" {
		t.Skip("explicit read-only configured-source preview required")
	}
	if value := strings.ToLower(os.Getenv("PROXY_SENTINEL_SRUN4K_REDIS_TLS")); value != "" && value != "false" && value != "0" {
		t.Fatal("plaintext preview refused for TLS deployment")
	}
	if port := os.Getenv("PROXY_SENTINEL_SRUN4K_REDIS_PORT"); port != "" && port != "16380" {
		t.Fatal("unexpected configured identity Redis port")
	}
	password := os.Getenv("PROXY_SENTINEL_SRUN4K_REDIS_PASSWORD")
	if password == "" {
		t.Fatal("credential missing")
	}
	source, sensor := os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_SOURCE"), os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_SENSOR")
	if !strings.HasPrefix(source, "srun4k:") || !strings.HasPrefix(sensor, "srun4k-direct:") {
		t.Fatal("explicit current managed authority required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := legacy4k.NewRedisOnlineClient(&redis.Options{Addr: "192.168.0.190:16380", Password: password, DialTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 3 * time.Second, MaxRetries: 1})
	defer client.Close()
	inventory, err := legacy4k.ReadOnlineInventoryPaged(ctx, client, "list:rad_online", 100000, 2000)
	if err != nil {
		t.Fatal("configured source read rejected")
	}
	records, coverage, err := inventory.IdentityRecordsWithStatsContext(ctx)
	if err != nil {
		t.Fatal("configured identity projection rejected")
	}
	count := len(records)
	request := identitySnapshotRequest{IdentityScope: store.IdentityScope{Source: source, SensorID: sensor}, ObservedAt: inventory.ObservedAt, IntervalSeconds: 21600, Complete: true, ExpectedCount: &count, Records: records}
	id, err := srunIdentitySnapshotIDContext(ctx, request)
	if err != nil {
		t.Fatal("configured snapshot hashing rejected")
	}
	expectedID, err := snapshotIDJSONReference(request)
	if err != nil || id != expectedID {
		t.Fatal("configured snapshot ID changed")
	}
	now := time.Now().UTC()
	got, err := prepareIdentitySnapshotContext(ctx, request, id, now, legacy4k.MaxIdentityAddressRecords)
	if err != nil {
		t.Fatal("configured complete conversion rejected")
	}
	expected, err := prepareIdentitySnapshotJSONReference(request, id, now, legacy4k.MaxIdentityAddressRecords)
	if err != nil {
		t.Fatal("configured reference conversion rejected")
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatal("configured normalized events or event IDs differ")
	}
	t.Logf("read-only configured preview: accounts=%d sessions=%d addresses=%d normalized_events=%d identical_ids_and_fields=true persisted=false", coverage.Accounts, coverage.Sessions, coverage.AddressRecords, len(got.Events))
}
