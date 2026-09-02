package store

import (
	"testing"
	"time"
)

func TestClickHouseRequestTimeoutDefaultsAndOverrides(t *testing.T) {
	defaultStore, err := NewClickHouseStore(ClickHouseOptions{DSN: "http://127.0.0.1:8123"})
	if err != nil {
		t.Fatal(err)
	}
	if defaultStore.client.Timeout != 2*time.Minute {
		t.Fatalf("unexpected default timeout: %s", defaultStore.client.Timeout)
	}

	explicitStore, err := NewClickHouseStore(ClickHouseOptions{DSN: "http://127.0.0.1:8123", RequestTimeout: 7 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if explicitStore.client.Timeout != 7*time.Minute {
		t.Fatalf("unexpected explicit timeout: %s", explicitStore.client.Timeout)
	}
}
