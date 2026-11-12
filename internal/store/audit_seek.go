package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AuditSeekPage struct {
	Logs       []AuditLog `json:"logs"`
	NextCursor string     `json:"next_cursor"`
	HasMore    bool       `json:"has_more"`
	Snapshot   time.Time  `json:"snapshot"`
}

type auditSeekCursor struct {
	Snapshot time.Time `json:"snapshot"`
	At       time.Time `json:"at"`
	ID       string    `json:"id"`
	Query    string    `json:"query"`
}

func decodeAuditSeekCursor(raw, query string) (auditSeekCursor, error) {
	var cursor auditSeekCursor
	if raw == "" {
		cursor.Snapshot = time.Now().UTC()
		cursor.Query = query
		return cursor, nil
	}
	if len(raw) > 1024 {
		return cursor, fmt.Errorf("invalid audit cursor")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Snapshot.IsZero() || cursor.At.IsZero() || cursor.ID == "" || cursor.Query != query {
		return auditSeekCursor{}, fmt.Errorf("invalid audit cursor")
	}
	return cursor, nil
}

func encodeAuditSeekCursor(cursor auditSeekCursor) string {
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// ListAuditLogsSeek reads one bounded page. Exact counts remain in the legacy
// endpoint and never run as a prerequisite for the normal audit list.
func (s *PostgresStore) ListAuditLogsSeek(ctx context.Context, limit int, rawCursor, query string) (AuditSeekPage, error) {
	var page AuditSeekPage
	if limit < 1 || limit > 50 {
		return page, fmt.Errorf("audit limit must be 1..50")
	}
	query = strings.ToLower(strings.TrimSpace(query))
	cursor, err := decodeAuditSeekCursor(rawCursor, query)
	if err != nil {
		return page, err
	}
	page.Snapshot = cursor.Snapshot
	pattern := "%" + query + "%"
	sqlQuery := `SELECT audit_id,actor,action,target,outcome,created_at FROM audit_logs
 WHERE created_at<=$1 AND ($2='' OR lower(actor||' '||action||' '||target||' '||outcome) LIKE $3)`
	args := []any{cursor.Snapshot, query, pattern}
	if cursor.ID != "" {
		sqlQuery += ` AND (created_at,audit_id)<($4,$5)`
		args = append(args, cursor.At, cursor.ID)
	}
	sqlQuery += fmt.Sprintf(` ORDER BY created_at DESC,audit_id DESC LIMIT $%d`, len(args)+1)
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	page.Logs = make([]AuditLog, 0, limit)
	for rows.Next() {
		var item AuditLog
		var created time.Time
		if err := rows.Scan(&item.AuditID, &item.Actor, &item.Action, &item.Target, &item.Outcome, &created); err != nil {
			return AuditSeekPage{}, err
		}
		if len(page.Logs) == limit {
			page.HasMore = true
			break
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339Nano)
		page.Logs = append(page.Logs, item)
		cursor.At, cursor.ID = created, item.AuditID
	}
	if err := rows.Err(); err != nil {
		return AuditSeekPage{}, err
	}
	if page.HasMore {
		page.NextCursor = encodeAuditSeekCursor(cursor)
	}
	return page, nil
}

func (s *DBStore) ListAuditLogsSeek(ctx context.Context, limit int, cursor, query string) (AuditSeekPage, error) {
	return s.pg.ListAuditLogsSeek(ctx, limit, cursor, query)
}

// GetAuditLog uses the unique audit ID rather than reading an arbitrary prefix
// of the audit history and failing to find older records.
func (s *PostgresStore) GetAuditLog(ctx context.Context, id string) (AuditLog, bool, error) {
	var item AuditLog
	var created time.Time
	err := s.db.QueryRowContext(ctx, `SELECT audit_id,actor,action,target,outcome,created_at FROM audit_logs WHERE audit_id=$1`, id).
		Scan(&item.AuditID, &item.Actor, &item.Action, &item.Target, &item.Outcome, &created)
	if err == sql.ErrNoRows {
		return AuditLog{}, false, nil
	}
	if err != nil {
		return AuditLog{}, false, err
	}
	item.CreatedAt = created.UTC().Format(time.RFC3339Nano)
	return item, true, nil
}

func (s *DBStore) GetAuditLog(ctx context.Context, id string) (AuditLog, bool, error) {
	return s.pg.GetAuditLog(ctx, id)
}
