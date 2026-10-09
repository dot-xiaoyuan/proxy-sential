package identity

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeRecordMatchesJSONConvert(t *testing.T) {
	for _, name := range []string{"plain", "empty_options", "raw_values", "raw_keys", "raw_source_option", "raw_sensor_option", "raw_source_with_empty_sensor", "html_unicode", "nan", "positive_inf", "negative_inf", "missing_timestamp"} {
		t.Run(name, func(t *testing.T) {
			fields := map[string]string{"timestamp": "2026-10-01T03:00:00.123Z", "account_id": "alice", "ip": "192.0.2.1", "session_id": "one", "mac": "AABB.CCDD.EEFF", "product_id": "1"}
			opts := Options{Source: "radius", SensorID: "sensor"}
			switch name {
			case "empty_options":
				opts = Options{}
			case "raw_values":
				fields["account_id"] = "a\xff\xff\xfe"
				fields["department"] = "院\xff系"
			case "raw_keys":
				fields["ignored_\xff"] = "last"
				fields["ignored_\xfe"] = "first"
			case "raw_source_option":
				opts.Source = "radius-\xff"
			case "raw_sensor_option":
				opts.SensorID = "sensor-\xfe"
			case "raw_source_with_empty_sensor":
				opts = Options{Source: "radius-\xff"}
			case "html_unicode":
				fields["department"] = "院系 <A&B>\n\u2028\u2029"
				fields["access_type"] = "宿舍\tWi-Fi"
			case "nan":
				fields["identity_confidence"] = "NaN"
			case "positive_inf":
				fields["identity_confidence"] = "+Inf"
			case "negative_inf":
				fields["identity_confidence"] = "-Inf"
			case "missing_timestamp":
				delete(fields, "timestamp")
			}
			before, _ := json.Marshal(fields)
			var output bytes.Buffer
			stats, referenceErr := Convert(bytes.NewReader(before), &output, opts)
			got, err := NormalizeRecord(fields, 1, opts)
			expectedOK := referenceErr == nil && stats.Emitted == 1
			if (err == nil) != expectedOK {
				t.Fatalf("acceptance changed: direct=%v reference=%v stats=%+v", err, referenceErr, stats)
			}
			if expectedOK {
				var expected normalized.Event
				if err := json.Unmarshal(output.Bytes(), &expected); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, expected) {
					t.Fatalf("normalized event/ID differs: direct=%+v reference=%+v", got, expected)
				}
			} else if !reflect.DeepEqual(got, normalized.Event{}) {
				t.Fatal("failed record returned partial event")
			}
			after, _ := json.Marshal(fields)
			if !bytes.Equal(before, after) {
				t.Fatal("input mutated")
			}
		})
	}
}
func TestIdentityJSONStringBudgetMatchesEncodingJSON(t *testing.T) {
	values := []string{"", "plain", "中文 <>&\u2028\u2029", "\xff\xff\xe2\x80", "valid\ufffd"}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	values = append(values, string(all))
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		remaining, valid, fits := consumeIdentityJSONString(value, len(raw))
		if !fits || remaining != 0 || valid != utf8.ValidString(value) {
			t.Fatalf("exact encoded size differs: length=%d remaining=%d valid=%v fits=%v", len(raw), remaining, valid, fits)
		}
		if _, _, fits := consumeIdentityJSONString(value, len(raw)-1); fits {
			t.Fatal("encoded string plus one accepted")
		}
	}
}
func TestIdentityJSONRecordBudgetPreservesScannerBoundary(t *testing.T) {
	for _, size := range []int{maxJSONLRecordBytes - 1, maxJSONLRecordBytes, maxJSONLRecordBytes + 1} {
		fields := map[string]string{"timestamp": "2026-10-01T03:00:00Z", "account_id": "alice", "ip": "192.0.2.1", "ignored": ""}
		base, _ := json.Marshal(fields)
		fields["ignored"] = strings.Repeat("x", size-len(base))
		raw, _ := json.Marshal(fields)
		if len(raw) != size {
			t.Fatal("fixture size differs")
		}
		valid, fits := identityJSONRecordBudget(fields)
		records, err := parseJSONL(bytes.NewReader(raw))
		if (fits && !valid) || fits != (err == nil) || fits != (size < maxJSONLRecordBytes) {
			t.Fatalf("scanner boundary changed: bytes=%d direct=%v scanner=%v", size, fits, err)
		}
		if fits && len(records) != 1 {
			t.Fatal("accepted token lost record")
		}
	}
}
func TestNormalizeRecordMapsAreIndependent(t *testing.T) {
	fields := map[string]string{"timestamp": "2026-10-01T03:00:00Z", "account_id": "alice", "ip": "192.0.2.1", "product_id": "1"}
	a, err := NormalizeRecord(fields, 1, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NormalizeRecord(fields, 2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	a.Subject["account_id"] = "changed"
	a.Payload["product_id"] = "changed"
	a.RawRef["backend"] = "changed"
	fields["account_id"] = "input-changed"
	if b.Subject["account_id"] != "alice" || b.Payload["product_id"] != "1" || b.RawRef["backend"] != "identity" {
		t.Fatal("output or input map alias corrupted another event")
	}
	if a.EventID != b.EventID {
		t.Fatal("event ID depends on offset")
	}
}
