package store

import (
	"strings"
	"testing"
)

func TestIngestSourceLeaseKeyIsPostgresTextSafeAndUnambiguous(t *testing.T) {
	left := ingestSourceLeaseKey("sensor", "zeek-dns", "/var/log/a|b")
	right := ingestSourceLeaseKey("sensor|zeek", "dns", "/var/log/a|b")
	if strings.ContainsRune(left, 0) {
		t.Fatal("lease key contains a PostgreSQL text NUL byte")
	}
	if left == right {
		t.Fatal("length-prefixed lease key collided")
	}
}
