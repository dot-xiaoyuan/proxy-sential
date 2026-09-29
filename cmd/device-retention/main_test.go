package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"proxy-sentinel/internal/store"
)

func TestRetentionRetryUsesActualBatch(t *testing.T) {
	timeout := &pgconn.PgError{Code: "57014"}
	for _, tt := range []struct {
		name       string
		err        error
		size, next int
		retry      bool
	}{
		{"one oversized row", &store.DeviceRetentionBatchError{Rows: 1, InventoryBytes: 81 << 20, Err: timeout}, 500, 500, true},
		{"byte limited batch", &store.DeviceRetentionBatchError{Rows: 20, InventoryBytes: 8 << 20, Err: timeout}, 500, 10, true},
		{"lock contention", &pgconn.PgError{Code: "55P03"}, 125, 125, true},
		{"ordinary timeout", timeout, 125, 62, true},
		{"cancellation", context.Canceled, 125, 125, false},
		{"invalid data", &pgconn.PgError{Code: "22P02"}, 125, 125, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			size, _, retry := retentionRetry(fmt.Errorf("outer: %w", tt.err), tt.size)
			if size != tt.next || retry != tt.retry {
				t.Fatal(size, retry)
			}
		})
	}
}
