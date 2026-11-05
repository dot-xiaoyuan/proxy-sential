// Package pagination locates numbered pages on existing ordered read indexes.
// Position queries return a single boundary key; list queries remain keyset
// queries and decode only the requested page, never the preceding payloads.
package pagination

import (
	"errors"
	"fmt"
	"time"
)

var ErrPageOutOfRange = errors.New("requested page no longer exists; refresh the list")

type Position struct {
	Page   int       `json:"page"`
	Limit  int       `json:"limit"`
	Cursor string    `json:"cursor"`
	AsOf   time.Time `json:"as_of"`
}

type Metadata struct {
	Total int64     `json:"total"`
	AsOf  time.Time `json:"as_of"`
}

// BoundaryOffset is the zero-based index immediately before a requested page.
// Page one has no preceding record and therefore uses the empty cursor.
func BoundaryOffset(page, limit int) (int64, error) {
	if page < 1 || page > 1_000_000_000 || limit < 1 || limit > 200 {
		return 0, fmt.Errorf("page must be between 1 and 1000000000; limit must be between 1 and 200")
	}
	return int64(page-1)*int64(limit) - 1, nil
}
