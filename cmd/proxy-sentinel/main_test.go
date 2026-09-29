package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenOutputWithParentsCreatesNestedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow", "evaluation", "latest.json")
	output, closeOutput, err := openOutputWithParents(path)
	if err != nil {
		t.Fatalf("open nested output: %v", err)
	}
	if _, err := output.WriteString("{}\n"); err != nil {
		t.Fatalf("write nested output: %v", err)
	}
	if err := closeOutput(); err != nil {
		t.Fatalf("close nested output: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("nested output was not created: %v", err)
	}
}
