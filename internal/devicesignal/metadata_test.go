package devicesignal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestObservedInterfaceReadsNewestRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ttl.jsonl")
	records := strings.Join([]string{
		`{"event_id":"device-1","observer":{"sensor_id":"ncu-184","interface":"enp2s0f0"}}`,
		`{"event_id":"device-2","observer":{"sensor_id":"ncu-184","interface":"bond0"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(records), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ObservedInterface(path); got != "bond0" {
		t.Fatalf("ObservedInterface = %q, want bond0", got)
	}
}

func TestObservedInterfaceSkipsUnreadableTailRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ttl.jsonl")
	records := strings.Join([]string{
		`{"event_id":"device-1","observer":{"interface":"bond0"}}`,
		`not json at all`,
		`{"event_id":"device-2","observer":{"interface":"   "}}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(records), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ObservedInterface(path); got != "bond0" {
		t.Fatalf("ObservedInterface = %q, want the last readable interface bond0", got)
	}
}

// A rotated file must still report the newest interface even when the tail
// window starts in the middle of a record.
func TestObservedInterfaceReadsPastTheTailWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ttl.jsonl")
	filler := `{"event_id":"device-filler","observer":{"interface":"enp8s0f0"},"payload":{"padding":"` + strings.Repeat("x", 512) + `"}}` + "\n"
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(strings.Repeat(filler, 4*(metadataTailBytes/len(filler)+1))); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"event_id":"device-last","observer":{"interface":"bond0"}}` + "\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if got := ObservedInterface(path); got != "bond0" {
		t.Fatalf("ObservedInterface = %q, want bond0", got)
	}
}

func TestObservedInterfaceHandlesMissingAndEmptyFiles(t *testing.T) {
	directory := t.TempDir()
	empty := filepath.Join(directory, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing": filepath.Join(directory, "absent.jsonl"),
		"empty":   empty,
		"blank":   "   ",
	} {
		if got := ObservedInterface(path); got != "" {
			t.Fatalf("%s: ObservedInterface = %q, want empty", name, got)
		}
	}
}
