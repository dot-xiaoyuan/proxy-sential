package store

import (
	"strings"
	"testing"
)

// The sequence index is partial. Omitting the protocol predicate makes every
// acknowledgement scan retained batch history even though it needs one row.
func TestIdentityProgressUsesProtocolTwoSequenceIndex(t *testing.T) {
	if !strings.Contains(applyScopeProgressSQL, "FROM identity_ingest_batches WHERE protocol_version=2 AND scope_key=$1 AND sequence=") {
		t.Fatal("next pending batch must match the protocol-2 sequence index predicate")
	}
}
