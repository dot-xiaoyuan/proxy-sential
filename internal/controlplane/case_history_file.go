package controlplane

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"proxy-sentinel/internal/store"
)

func (s *Server) caseHistoryFile(w http.ResponseWriter, r *http.Request, id, kind string) {
	if _, ok := caseHistorySources[kind]; !ok {
		writeError(w, 400, "bad_history_kind", "unknown history kind")
		return
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, 400, "bad_page", err.Error())
		return
	}
	offset, err := cursorOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, 400, "bad_page", err.Error())
		return
	}
	s.operations.mu.Lock()
	item, found := s.operations.doc.Cases[id]
	var rows []any
	switch kind {
	case "evidence":
		for _, row := range item.EvidenceHistory {
			rows = append(rows, row)
		}
	case "comments":
		for _, row := range item.Comments {
			rows = append(rows, row)
		}
	case "timeline":
		for _, row := range item.Timeline {
			rows = append(rows, row)
		}
	}
	s.operations.mu.Unlock()
	if !found {
		writeError(w, 404, "case_not_found", "case not found")
		return
	}
	type record struct {
		raw     json.RawMessage
		created time.Time
		id      string
	}
	ordered := make([]record, 0, len(rows))
	for _, row := range rows {
		raw, _ := json.Marshal(row)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		var created, rowID string
		_ = json.Unmarshal(fields["created_at"], &created)
		for _, key := range []string{"snapshot_id", "comment_id", "event_id"} {
			if value := fields[key]; value != nil {
				_ = json.Unmarshal(value, &rowID)
				break
			}
		}
		stamp, _ := time.Parse(time.RFC3339Nano, created)
		ordered = append(ordered, record{raw, stamp, rowID})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].created.Equal(ordered[j].created) {
			return ordered[i].id > ordered[j].id
		}
		return ordered[i].created.After(ordered[j].created)
	})
	items := []json.RawMessage{}
	for i := offset; i < len(ordered) && i < offset+limit; i++ {
		items = append(items, ordered[i].raw)
	}
	var next *string
	if offset+limit < len(ordered) {
		cursor := strconv.Itoa(offset + limit)
		next = &cursor
	}
	writeJSON(w, 200, map[string]any{"items": items, "page": store.Page{Limit: limit, Total: len(ordered), NextCursor: next}})
}
