package store

import (
	"context"
	"testing"
	"time"
)

func TestParseSignalArrivalsReadsClickHouseRows(t *testing.T) {
	rows := []byte("packet-sidecar\tttl\t1760241210000\t42\nncu-srun4k\tidentity\t1760241250500\t0\n")
	got, err := parseSignalArrivals(rows)
	if err != nil || len(got) != 2 {
		t.Fatalf("parse: %+v %v", got, err)
	}
	if got[0].Source != "packet-sidecar" || got[0].SourceEventType != "ttl" || got[0].AgeSeconds != 42 || !got[0].LastSeen.Equal(time.UnixMilli(1760241210000)) {
		t.Fatalf("row: %+v", got[0])
	}
	if _, err := parseSignalArrivals([]byte("zeek\tdhcp\tnot-a-number\t1\n")); err == nil {
		t.Fatal("malformed timestamp accepted")
	}
	if _, err := parseSignalArrivals([]byte("zeek\tdhcp\n")); err == nil {
		t.Fatal("short row accepted")
	}
}

func TestSignalArrivalsRejectsUnboundedLookback(t *testing.T) {
	s := &ClickHouseStore{}
	for _, lookback := range []time.Duration{0, 72 * time.Hour} {
		if _, err := s.SignalArrivals(context.Background(), lookback); err == nil {
			t.Fatalf("lookback %v accepted", lookback)
		}
	}
}
