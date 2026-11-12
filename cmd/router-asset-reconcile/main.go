// Command router-asset-reconcile compares bounded current-state key pages in a
// read-only PostgreSQL snapshot. A segment anchors the source epoch and offset;
// current-state rows have no segment-to-result-version history, so this tool
// never claims to reconstruct the state at that historical segment boundary.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const routerKeyPageSQL = `WITH stream_keys AS MATERIALIZED (
 SELECT device_key FROM stream_discovery_device_state
 WHERE epoch=$1 AND device_key>$2 ORDER BY device_key LIMIT $3
), shadow_keys AS MATERIALIZED (
 SELECT device_key FROM discovery_device_current_shadow
 WHERE document ? 'epoch' AND document->>'epoch'=$1 AND device_key>$2
 ORDER BY device_key LIMIT $3
)
SELECT device_key FROM (
 SELECT device_key FROM stream_keys UNION SELECT device_key FROM shadow_keys
) keys ORDER BY device_key LIMIT $3`

type options struct {
	Epoch, SegmentID, AfterKey string
	MaxVersion                 int64
	PageSize, MaxPages         int
}

type assetRow struct {
	Key, Epoch string
	Version    int64
	LastSeen   time.Time
	ExpiresAt  *time.Time
	Document   map[string]any
	Facts      map[string]any
}

type fieldValues struct {
	Stream any `json:"stream"`
	Shadow any `json:"shadow"`
}

type assetDifference struct {
	Key           string                 `json:"device_key"`
	Status        string                 `json:"status"`
	StreamVersion int64                  `json:"stream_version,omitempty"`
	ShadowVersion int64                  `json:"shadow_version,omitempty"`
	Fields        []string               `json:"fields,omitempty"`
	Values        map[string]fieldValues `json:"values,omitempty"`
	Unverified    []string               `json:"unverified,omitempty"`
}

type segmentAnchor struct {
	ID           string         `json:"segment_id"`
	Epoch        string         `json:"epoch"`
	SourceKind   string         `json:"source_kind"`
	SourcePath   string         `json:"source_path"`
	SourceFileID sql.NullString `json:"-"`
	StartOffset  sql.NullInt64  `json:"-"`
	EndOffset    sql.NullInt64  `json:"-"`
	AcceptedAt   time.Time      `json:"accepted_at"`
	ProjectedAt  time.Time      `json:"projected_at"`
	EventCount   int            `json:"event_count"`
}

type versionGap struct {
	After   int64 `json:"after_result_version"`
	Through int64 `json:"through_result_version"`
}

type report struct {
	Segment                 segmentAnchor     `json:"segment"`
	SourceFileID            string            `json:"source_file_id,omitempty"`
	SourceState             string            `json:"source_state"`
	StartOffset             *int64            `json:"source_start_offset,omitempty"`
	EndOffset               *int64            `json:"source_end_offset,omitempty"`
	SnapshotAt              time.Time         `json:"snapshot_at"`
	CutoffVersion           int64             `json:"cutoff_result_version"`
	StreamMaxVersion        int64             `json:"stream_max_result_version"`
	ShadowProgressVersion   int64             `json:"shadow_progress_result_version"`
	ShadowProgressUpdatedAt *time.Time        `json:"shadow_progress_updated_at,omitempty"`
	UncoveredWatermark      *versionGap       `json:"uncovered_watermark,omitempty"`
	RowsExamined            int               `json:"keys_examined"`
	RouterRows              int               `json:"router_rows"`
	MatchingRows            int               `json:"matching_rows"`
	PartialRows             int               `json:"partially_verified_rows"`
	DifferentRows           int               `json:"different_rows"`
	UncoveredRows           int               `json:"uncovered_rows"`
	UnverifiedExpiryRows    int               `json:"unverified_expiry_rows"`
	Differences             []assetDifference `json:"differences"`
	HasMore                 bool              `json:"has_more"`
	NextAfterKey            string            `json:"next_after_key,omitempty"`
	Limitations             []string          `json:"limitations"`
}

func main() {
	var opts options
	flag.StringVar(&opts.Epoch, "epoch", "", "fixed source epoch")
	flag.StringVar(&opts.SegmentID, "segment-id", "", "segment ledger ID used as source/offset anchor")
	flag.StringVar(&opts.AfterKey, "after-key", "", "resume key; a new process has a new database snapshot")
	flag.Int64Var(&opts.MaxVersion, "through-version", 0, "fixed result-version ceiling; zero pins this run's snapshot maximum")
	flag.IntVar(&opts.PageSize, "page-size", 100, "device keys per indexed page, 1..200")
	flag.IntVar(&opts.MaxPages, "max-pages", 5, "pages in one read-only snapshot, 1..20")
	flag.Parse()
	if err := validateOptions(opts); err != nil {
		fail(err)
	}
	dsn := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if dsn == "" {
		fail(errors.New("PROXY_SENTINEL_POSTGRES_DSN is required"))
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fail(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := reconcile(ctx, db, opts)
	if err != nil {
		fail(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func validateOptions(opts options) error {
	if opts.Epoch == "" || opts.SegmentID == "" || opts.PageSize < 1 || opts.PageSize > 200 || opts.MaxPages < 1 || opts.MaxPages > 20 || opts.MaxVersion < 0 {
		return errors.New("epoch, segment-id, page-size 1..200, max-pages 1..20 and nonnegative through-version are required")
	}
	return nil
}

func reconcile(ctx context.Context, db *sql.DB, opts options) (report, error) {
	var out report
	if err := validateOptions(opts); err != nil {
		return out, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT segment_id,epoch,source_kind,source_path,source_file_id,source_start_offset,source_end_offset,accepted_at,projected_at,event_count
 FROM stream_projection_segments WHERE segment_id=$1 AND epoch=$2`, opts.SegmentID, opts.Epoch).Scan(
		&out.Segment.ID, &out.Segment.Epoch, &out.Segment.SourceKind, &out.Segment.SourcePath,
		&out.Segment.SourceFileID, &out.Segment.StartOffset, &out.Segment.EndOffset,
		&out.Segment.AcceptedAt, &out.Segment.ProjectedAt, &out.Segment.EventCount); err != nil {
		return out, fmt.Errorf("segment anchor: %w", err)
	}
	if out.Segment.SourceFileID.Valid {
		out.SourceFileID = out.Segment.SourceFileID.String
	}
	if out.Segment.StartOffset.Valid {
		v := out.Segment.StartOffset.Int64
		out.StartOffset = &v
	}
	if out.Segment.EndOffset.Valid {
		v := out.Segment.EndOffset.Int64
		out.EndOffset = &v
	}
	if err := tx.QueryRowContext(ctx, `SELECT state FROM stream_source_cutovers
 WHERE epoch=$1 AND source_kind=$2 AND source_path=$3`, opts.Epoch, out.Segment.SourceKind, out.Segment.SourcePath).Scan(&out.SourceState); err != nil {
		return out, fmt.Errorf("source cutover: %w", err)
	}
	if out.SourceState != "active" {
		return out, fmt.Errorf("source cutover %s is %s; the route page reads active epochs", out.Segment.SourcePath, out.SourceState)
	}
	if err := tx.QueryRowContext(ctx, `SELECT transaction_timestamp(),coalesce((SELECT result_version FROM stream_discovery_device_state
 WHERE epoch=$1 ORDER BY result_version DESC LIMIT 1),0)`, opts.Epoch).Scan(&out.SnapshotAt, &out.StreamMaxVersion); err != nil {
		return out, fmt.Errorf("stream watermark: %w", err)
	}
	var progressAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT last_result_version,updated_at FROM discovery_current_stream_progress WHERE epoch=$1`, opts.Epoch).Scan(&out.ShadowProgressVersion, &progressAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, fmt.Errorf("shadow watermark: %w", err)
	}
	if progressAt.Valid {
		out.ShadowProgressUpdatedAt = &progressAt.Time
	}
	if out.ShadowProgressVersion < out.StreamMaxVersion {
		out.UncoveredWatermark = &versionGap{After: out.ShadowProgressVersion, Through: out.StreamMaxVersion}
	}
	out.CutoffVersion = out.StreamMaxVersion
	if opts.MaxVersion > 0 {
		if opts.MaxVersion > out.StreamMaxVersion {
			return out, fmt.Errorf("through-version %d exceeds snapshot stream maximum %d", opts.MaxVersion, out.StreamMaxVersion)
		}
		out.CutoffVersion = opts.MaxVersion
	}
	out.Limitations = []string{
		"segment ledger has no device-key or result-version interval; this compares current rows within the pinned epoch, not a historical segment snapshot",
		"only rows with equal stream and shadow result versions can establish field agreement; lagging or missing shadow rows are uncovered",
		"shadow rows without a recorded epoch cannot be assigned to this source epoch",
		"evidence comparison uses classification.evidence_ids from current documents; full body_ref evidence is outside the current-state page",
		"a new invocation takes a new MVCC snapshot; use one bounded run for a consistent comparison window",
	}
	out.Differences = []assetDifference{}
	after := opts.AfterKey
	for page := 0; page < opts.MaxPages; page++ {
		keys, more, err := loadKeyPage(ctx, tx, opts.Epoch, after, opts.PageSize)
		if err != nil {
			return out, err
		}
		if len(keys) == 0 {
			out.HasMore = false
			break
		}
		stream, err := loadStreamRows(ctx, tx, opts.Epoch, keys)
		if err != nil {
			return out, err
		}
		shadow, err := loadShadowRows(ctx, tx, keys)
		if err != nil {
			return out, err
		}
		for _, key := range keys {
			out.RowsExamined++
			s, c := stream[key], shadow[key]
			if !routerRelevant(s) && !routerRelevant(c) {
				continue
			}
			out.RouterRows++
			diff := compareRouterRows(s, c, out.CutoffVersion)
			switch diff.Status {
			case "matched":
				out.MatchingRows++
			case "partial_match":
				out.PartialRows++
				out.Differences = append(out.Differences, diff)
			case "different":
				out.DifferentRows++
				out.Differences = append(out.Differences, diff)
			default:
				out.UncoveredRows++
				out.Differences = append(out.Differences, diff)
			}
			if len(diff.Unverified) > 0 {
				out.UnverifiedExpiryRows++
			}
		}
		after = keys[len(keys)-1]
		out.HasMore = more
		if !more {
			break
		}
	}
	if out.HasMore {
		out.NextAfterKey = after
	}
	return out, tx.Commit()
}

func loadKeyPage(ctx context.Context, tx *sql.Tx, epoch, after string, size int) ([]string, bool, error) {
	rows, err := tx.QueryContext(ctx, routerKeyPageSQL, epoch, after, size+1)
	if err != nil {
		return nil, false, fmt.Errorf("device key page: %w", err)
	}
	defer rows.Close()
	keys := make([]string, 0, size+1)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, false, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(keys) > size
	if more {
		keys = keys[:size]
	}
	return keys, more, nil
}

func loadStreamRows(ctx context.Context, tx *sql.Tx, epoch string, keys []string) (map[string]*assetRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT device_key,result_version,last_seen,expires_at,document FROM stream_discovery_device_state
 WHERE epoch=$1 AND device_key=ANY($2::text[])`, epoch, keys)
	if err != nil {
		return nil, fmt.Errorf("stream device page: %w", err)
	}
	defer rows.Close()
	result := make(map[string]*assetRow, len(keys))
	for rows.Next() {
		row := &assetRow{Epoch: epoch}
		var expiry sql.NullTime
		var raw []byte
		if err := rows.Scan(&row.Key, &row.Version, &row.LastSeen, &expiry, &raw); err != nil {
			return nil, err
		}
		if expiry.Valid {
			row.ExpiresAt = &expiry.Time
		}
		if err := json.Unmarshal(raw, &row.Document); err != nil {
			return nil, err
		}
		result[row.Key] = row
	}
	return result, rows.Err()
}

func loadShadowRows(ctx context.Context, tx *sql.Tx, keys []string) (map[string]*assetRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT device_key,stream_result_version,last_seen,document,facts FROM discovery_device_current_shadow
 WHERE device_key=ANY($1::text[])`, keys)
	if err != nil {
		return nil, fmt.Errorf("shadow device page: %w", err)
	}
	defer rows.Close()
	result := make(map[string]*assetRow, len(keys))
	for rows.Next() {
		row := &assetRow{}
		var doc, facts []byte
		if err := rows.Scan(&row.Key, &row.Version, &row.LastSeen, &doc, &facts); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(doc, &row.Document); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(facts, &row.Facts); err != nil {
			return nil, err
		}
		row.Epoch = stringField(row.Document, "epoch")
		result[row.Key] = row
	}
	return result, rows.Err()
}

func routerRelevant(row *assetRow) bool {
	if row == nil {
		return false
	}
	for _, key := range []string{"device_type", "last_device_type"} {
		if kind := stringField(row.Document, key); kind == "router" || kind == "access_point" {
			return true
		}
	}
	return false
}

func compareRouterRows(stream, shadow *assetRow, cutoff int64) assetDifference {
	diff := assetDifference{}
	if stream != nil {
		diff.Key, diff.StreamVersion = stream.Key, stream.Version
	}
	if shadow != nil {
		diff.Key, diff.ShadowVersion = shadow.Key, shadow.Version
	}
	switch {
	case stream == nil:
		diff.Status = "shadow_only"
		return diff
	case stream.Version > cutoff:
		diff.Status = "stream_advanced"
		return diff
	case shadow == nil || shadow.Epoch != stream.Epoch || shadow.Version != stream.Version || shadow.Version == 0:
		diff.Status = "shadow_uncovered"
		return diff
	case shadow.Document["current"] == false:
		diff.Status = "shadow_not_visible"
		return diff
	}
	diff.Status = "matched"
	add := func(name string, a, b any) {
		if !equalJSON(a, b) {
			diff.Fields = append(diff.Fields, name)
			if diff.Values == nil {
				diff.Values = map[string]fieldValues{}
			}
			diff.Values[name] = fieldValues{a, b}
		}
	}
	add("device_type", stringField(stream.Document, "device_type"), stringField(shadow.Document, "device_type"))
	add("last_device_type", stringField(stream.Document, "last_device_type"), stringField(shadow.Document, "last_device_type"))
	add("classification_status", stringField(stream.Document, "classification_status"), stringField(shadow.Document, "classification_status"))
	// The old shadow API forces current=true for rows it admits.
	add("current", stream.Document["current"], true)
	if !stream.LastSeen.IsZero() && !shadow.LastSeen.IsZero() {
		add("last_seen", stream.LastSeen.UTC(), shadow.LastSeen.UTC())
	}
	add("current_addresses", stringSet(addresses(stream)), stringSet(addresses(shadow)))
	add("evidence_refs", stringSet(evidenceRefs(stream)), stringSet(evidenceRefs(shadow)))
	if stream.ExpiresAt != nil {
		if expiry, ok := parseTimeField(shadow.Document, "expires_at"); ok {
			add("expiry_boundary", stream.ExpiresAt.UTC(), expiry.UTC())
		} else {
			diff.Unverified = append(diff.Unverified, "expiry_boundary")
		}
	}
	if len(diff.Fields) > 0 {
		diff.Status = "different"
	} else if len(diff.Unverified) > 0 {
		diff.Status = "partial_match"
	}
	return diff
}

func stringField(doc map[string]any, key string) string {
	value, _ := doc[key].(string)
	return strings.TrimSpace(value)
}

func addresses(row *assetRow) []string {
	if row == nil {
		return nil
	}
	if len(row.Facts) > 0 {
		var found []string
		for _, value := range row.Facts {
			if fact, ok := value.(map[string]any); ok {
				if ip := stringField(fact, "ip"); ip != "" {
					found = append(found, ip)
				}
			}
		}
		if len(found) > 0 {
			return found
		}
	}
	value, ok := row.Document["current_addresses"]
	if !ok {
		value = row.Document["addresses"]
	}
	return stringArray(value)
}

func evidenceRefs(row *assetRow) []string {
	if row == nil {
		return nil
	}
	classification, _ := row.Document["classification"].(map[string]any)
	return stringArray(classification["evidence_ids"])
}

func stringArray(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			result = append(result, text)
		}
	}
	return result
}

func stringSet(items []string) []string {
	unique := make(map[string]struct{}, len(items))
	for _, item := range items {
		unique[item] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for item := range unique {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func parseTimeField(doc map[string]any, key string) (time.Time, bool) {
	value := stringField(doc, key)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
