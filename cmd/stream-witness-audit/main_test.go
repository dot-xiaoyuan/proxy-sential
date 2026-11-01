package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadManifestRejectsUnknownAndTrailingInput(t *testing.T) {
	base := `{"epoch":"e","source_kind":"s","source_path":"p","file_id":"f","start_offset":0,"end_offset":1,"segments":[]}`
	for _, raw := range []string{strings.Replace(base, `"segments":[]`, `"unexpected":true,"segments":[]`, 1), base + `{}`} {
		if _, _, err := readManifest(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted malformed input: %s", raw)
		}
	}
}

func TestReadManifestBoundsFileSize(t *testing.T) {
	if _, _, err := readManifest(bytes.NewReader(bytes.Repeat([]byte("x"), maxManifestBytes+1))); err == nil {
		t.Fatal("accepted oversized manifest")
	}
}
