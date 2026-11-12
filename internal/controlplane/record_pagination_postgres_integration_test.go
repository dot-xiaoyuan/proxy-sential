package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestActionSeekPaginationPostgres(t *testing.T) {
	s, _ := taskIntegrationServer(t)
	prefix := "seek-action-" + shortToken(10)
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { s.operations.db.Exec(`DELETE FROM enforcement_actions WHERE action_id LIKE $1`, prefix+"%") })
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("%s%d", prefix, i)
		if _, err := s.operations.db.Exec(`INSERT INTO enforcement_actions(action_id,idempotency_key,action_type,subject_type,subject_id,status,mode,created_by,created_at) VALUES($1,$1,'record','account',$1,'recorded','record_only','isolated-replay',$2)`, id, at); err != nil {
			t.Fatal(err)
		}
	}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 2; page++ {
		w := httptest.NewRecorder()
		path := "/api/v1/actions?seek=1&limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		s.actionReadPostgres(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("page %d: %d %s", page, w.Code, w.Body.String())
		}
		var result struct {
			Items      []EnforcementAction `json:"items"`
			NextCursor string              `json:"next_cursor"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		for _, item := range result.Items {
			if seen[item.ActionID] {
				t.Fatalf("duplicate %s", item.ActionID)
			}
			seen[item.ActionID] = true
		}
		cursor = result.NextCursor
	}
	for i := 0; i < 3; i++ {
		if !seen[fmt.Sprintf("%s%d", prefix, i)] {
			t.Fatalf("missing fixture %d", i)
		}
	}
}
