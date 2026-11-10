package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSameSourceFilePathResolvesAliases(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "device_dhcp_message.log")
	if err := os.WriteFile(real, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.log")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if !sameSourceFilePath(real, alias) {
		t.Fatal("symlinked alias must resolve to the same source file")
	}
	if !sameSourceFilePath(real, real) {
		t.Fatal("identical paths must match")
	}
	other := filepath.Join(dir, "dhcp.log")
	if err := os.WriteFile(other, []byte("y"), 0600); err != nil {
		t.Fatal(err)
	}
	if sameSourceFilePath(real, other) {
		t.Fatal("different files must not match")
	}
	if sameSourceFilePath(filepath.Join(dir, "missing"), real) {
		t.Fatal("unresolvable paths must not match")
	}
}
