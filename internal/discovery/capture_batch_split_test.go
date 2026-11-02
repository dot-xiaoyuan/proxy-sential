package discovery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSplitCaptureBatchPreservesOrderAndByteLimit(t *testing.T) {
	const maxBytes = 1 << 20
	var source []string
	for i := 0; i < 3; i++ {
		source = append(source, strings.Repeat(string('a'+rune(i)), maxBytes/2))
	}
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	batches, err := splitCaptureBatch(raw, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, batch := range batches {
		if len(batch) > maxBytes {
			t.Fatalf("split batch has %d bytes", len(batch))
		}
		var part []string
		if err := json.Unmarshal(batch, &part); err != nil {
			t.Fatal(err)
		}
		got = append(got, part...)
	}
	if len(batches) != 3 || len(got) != len(source) {
		t.Fatalf("split produced %d batches and %d events", len(batches), len(got))
	}
	for i := range source {
		if got[i] != source[i] {
			t.Fatalf("event %d changed", i)
		}
	}
}
