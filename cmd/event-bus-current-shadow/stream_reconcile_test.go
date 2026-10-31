package main

import (
	"bytes"
	"testing"
)

func TestStreamCurrentBatchPreservesPerEpochProgressAndByteBoundary(t *testing.T) {
	batch := newStreamCurrentBatch()
	for _, row := range []streamCurrentRow{
		{Epoch: "old", DeviceKey: "same", Version: 4, Document: []byte(`{"name":"old"}`)},
		{Epoch: "new", DeviceKey: "same", Version: 8, Document: []byte(`{"name":"new"}`)},
	} {
		accepted, err := batch.add(row)
		if err != nil || !accepted {
			t.Fatalf("valid row rejected: %v %v", accepted, err)
		}
	}
	if batch.selected["same"].Version != 8 || batch.versions["old"] != 4 || batch.versions["new"] != 8 {
		t.Fatalf("lost epoch progress or newest device state: %+v", batch)
	}
	oversized := streamCurrentRow{Epoch: "new", DeviceKey: "later", Version: 9, Document: bytes.Repeat([]byte{'x'}, streamCurrentBatchBytes)}
	accepted, err := batch.add(oversized)
	if err != nil || accepted || batch.versions["new"] != 8 {
		t.Fatalf("byte cap skipped a row or advanced progress: accepted=%v err=%v batch=%+v", accepted, err, batch)
	}
	first := newStreamCurrentBatch()
	if accepted, err := first.add(oversized); accepted || err == nil {
		t.Fatalf("oversized first row should fail visibly: accepted=%v err=%v", accepted, err)
	}
}
