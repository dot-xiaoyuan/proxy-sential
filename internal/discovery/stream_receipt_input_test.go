package discovery

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

type receiptLookupKeys []map[string]string

func (want receiptLookupKeys) Match(value driver.Value) bool {
	raw, ok := value.([]byte)
	if !ok {
		return false
	}
	var got []map[string]string
	return json.Unmarshal(raw, &got) == nil && reflect.DeepEqual(got, []map[string]string(want))
}

func BenchmarkStreamReceiptLookupInputEncoding(b *testing.B) {
	items := make([]streamPreparedDiscovery, 500)
	for i := range items {
		items[i].Receipt = streamDiscoveryReceipt{
			Scope: strings.Repeat("a", 32), Key: fmt.Sprintf("%062d-key", i), Hash: strings.Repeat("b", 64),
			Accepted: time.Date(2026, 10, 29, 0, 0, 0, 123456789, time.UTC), Result: "applied",
		}
	}
	for _, mode := range []string{"full_receipt", "lookup_key"} {
		b.Run(mode, func(b *testing.B) {
			encode := func() ([]byte, error) {
				if mode == "full_receipt" {
					input := make([]streamDiscoveryReceipt, 0, len(items))
					for _, item := range items {
						input = append(input, item.Receipt)
					}
					return json.Marshal(input)
				}
				input := make([]streamDiscoveryLookupKey, 0, len(items))
				for _, item := range items {
					input = append(input, streamDiscoveryLookupKey{Scope: item.Receipt.Scope, Key: item.Receipt.Key})
				}
				return json.Marshal(input)
			}
			raw, err := encode()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := encode(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(raw)), "json-bytes")
		})
	}
}

func TestStreamReceiptLookupUsesOnlyScopeAndEventKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	items := []streamPreparedDiscovery{
		{Receipt: streamDiscoveryReceipt{Scope: `scope"one`, Key: `key\\one`, Hash: "hash-one", Accepted: time.Now(), Result: "applied"}},
		{Receipt: streamDiscoveryReceipt{Scope: "scope-two", Key: "key-two", Hash: "hash-two", Accepted: time.Now(), Result: "rejected"}},
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM stream_discovery_event_keys r`).WithArgs("epoch", receiptLookupKeys{
		{"scope_id": `scope"one`, "event_key": `key\\one`},
		{"scope_id": "scope-two", "event_key": "key-two"},
	}).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(`scope"one`, `key\\one`, "stored-hash"))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadStreamDiscoveryReceipts(context.Background(), tx, "epoch", items)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[`scope"one`+"\x00"+`key\\one`] != "stored-hash" {
		t.Fatalf("lookup changed scope/key or stored hash: %#v", got)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
