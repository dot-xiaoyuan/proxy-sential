package discovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"strings"
)

func (r Repository) DrainSpool(ctx context.Context, dir string) error {
	entries, e := os.ReadDir(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	processed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if processed >= 100 {
			return nil
		}
		processed++
		path := filepath.Join(dir, entry.Name())
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var events []normalized.Event
		if e = json.Unmarshal(b, &events); e != nil {
			return e
		}
		if len(events) == 0 {
			continue
		}
		o, e := FromEvent(events[0])
		if e != nil {
			return e
		}
		s := Snapshot{ID: strings.TrimSuffix(entry.Name(), ".json"), SourceID: o.SourceID, ConfigVersion: o.ConfigVersion, At: o.ObservedAt, Events: events}
		if e = r.SaveSnapshot(ctx, s); e != nil {
			return e
		}
		if e = os.Remove(path); e != nil {
			return e
		}
	}
	return nil
}
