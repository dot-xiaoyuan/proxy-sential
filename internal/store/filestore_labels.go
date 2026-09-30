package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ListLabels keeps live historical sample reviews consistent with replay labels.
func (s *FileStore) ListLabels(ctx context.Context, limit int) ([]Label, error) {
	file, err := os.Open(filepath.Join(s.shadowDir, "labels.jsonl"))
	if os.IsNotExist(err) {
		return []Label{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	labels := []Label{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var label Label
		if err := json.Unmarshal(scanner.Bytes(), &label); err != nil {
			return nil, fmt.Errorf("decode historical review label: %w", err)
		}
		if label.LabelID != "" {
			labels = append(labels, label)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(labels) > limit {
		labels = labels[len(labels)-limit:]
	}
	return labels, nil
}
