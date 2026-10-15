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
		s := Snapshot{ID: strings.TrimSuffix(entry.Name(), ".json"), Events: events}
		if !r.PipelineV2 {
			o, parseErr := FromEvent(events[0])
			if parseErr != nil {
				return parseErr
			}
			s.SourceID, s.ConfigVersion, s.At = o.SourceID, o.ConfigVersion, o.ObservedAt
		}
		// V2 records each rejection in the durable event receipt. A malformed
		// first observation must not strand the rest of a valid input batch.
		if e = r.SaveSnapshot(ctx, s); e != nil {
			return e
		}
		if e = os.Remove(path); e != nil {
			return e
		}
		if r.Describe != nil {
			for _, event := range events {
				r.Describe(event)
			}
		}
	}
	return nil
}

func writeDurableSpool(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
