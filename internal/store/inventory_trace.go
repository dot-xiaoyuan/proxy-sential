package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"proxy-sentinel/internal/normalized"
	"strings"
	"time"
)

type InventoryAssociation struct {
	Kind             string  `json:"kind"`
	Value            string  `json:"value"`
	Source           string  `json:"source"`
	FirstSeen        string  `json:"first_seen"`
	LastSeen         string  `json:"last_seen"`
	ObservationCount int64   `json:"observation_count"`
	SessionCount     int64   `json:"session_count"`
	Confidence       float64 `json:"confidence"`
	EventID          string  `json:"event_id,omitempty"`
}
type EndpointObservation struct {
	RecordID      string  `json:"record_id"`
	Kind          string  `json:"kind"`
	Value         string  `json:"value"`
	Source        string  `json:"source"`
	ObservedAt    string  `json:"observed_at"`
	Confidence    float64 `json:"confidence"`
	EventID       string  `json:"event_id,omitempty"`
	EvidenceState string  `json:"evidence_state"`
	StartedAt     string  `json:"started_at,omitempty"`
	EndedAt       string  `json:"ended_at,omitempty"`
	EvidenceURL   string  `json:"evidence_url,omitempty"`
	SessionID     string  `json:"session_id,omitempty"`
}
type EndpointObservationQuery struct {
	Kind   string
	Value  string
	Source string
	Start  string
	End    string
	Cursor string
	Limit  int
}
type EndpointObservationPage struct {
	Items      []EndpointObservation    `json:"items"`
	NextCursor string                   `json:"next_cursor,omitempty"`
	State      InventoryProjectionState `json:"state"`
}
type InventoryDetail struct {
	Profile           EndpointIdentityProfile  `json:"profile"`
	Associations      []InventoryAssociation   `json:"associations"`
	AssociationCounts map[string]int           `json:"association_counts,omitempty"`
	State             InventoryProjectionState `json:"state"`
}
type InventoryTraceReader interface {
	GetDeviceInventoryDetail(context.Context, string) (InventoryDetail, bool, error)
	ListEndpointObservations(context.Context, string, EndpointObservationQuery) (EndpointObservationPage, error)
}
type InventorySnapshotEvidenceReader interface {
	GetInventorySnapshotEvidence(context.Context, string, string) (normalized.Event, bool, error)
}
type InventorySessionEvidenceReader interface {
	GetInventorySessionEvidence(context.Context, string, string) (AccountSession, bool, error)
}

func (s *DBStore) GetInventorySessionEvidence(ctx context.Context, id, record string) (AccountSession, bool, error) {
	return s.pg.GetInventorySessionEvidence(ctx, id, record)
}
func (s *PostgresStore) GetInventorySessionEvidence(ctx context.Context, id, record string) (AccountSession, bool, error) {
	var key [3]string
	if !strings.HasPrefix(record, "session:") || json.Unmarshal([]byte(strings.TrimPrefix(record, "session:")), &key) != nil {
		return AccountSession{}, false, fmt.Errorf("invalid session evidence reference")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT session_id,account_id,endpoint_id,host(ip),mac,access_id,source,started_at,ended_at,identity_confidence,raw_ref,policy_metadata FROM account_sessions WHERE endpoint_id=$1 AND source=$2 AND session_id=$3 AND ip=$4::inet`, id, key[0], key[1], key[2])
	if err != nil {
		return AccountSession{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return AccountSession{}, false, rows.Err()
	}
	v, err := scanAccountSession(rows)
	return v, err == nil, err
}

func (s *DBStore) GetInventorySnapshotEvidence(ctx context.Context, id, record string) (normalized.Event, bool, error) {
	return s.pg.GetInventorySnapshotEvidence(ctx, id, record)
}
func (s *PostgresStore) GetInventorySnapshotEvidence(ctx context.Context, id, record string) (normalized.Event, bool, error) {
	var refRaw []byte
	var eventID string
	err := s.db.QueryRowContext(ctx, `SELECT snapshot_ref,event_id FROM endpoint_inventory_snapshot_facts WHERE endpoint_id=$1 AND record_id=$2`, id, strings.TrimPrefix(record, "snapshot:")).Scan(&refRaw, &eventID)
	if err == sql.ErrNoRows {
		return normalized.Event{}, false, nil
	}
	if err != nil {
		return normalized.Event{}, false, err
	}
	var k [5]string
	if err = json.Unmarshal(refRaw, &k); err != nil {
		return normalized.Event{}, false, err
	}
	var raw []byte
	err = s.db.QueryRowContext(ctx, `SELECT document FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, k[0], k[1], k[2], k[3], k[4]).Scan(&raw)
	if err == sql.ErrNoRows {
		return normalized.Event{}, false, nil
	}
	if err != nil {
		return normalized.Event{}, false, err
	}
	var snap IdentitySnapshot
	if err = json.Unmarshal(raw, &snap); err != nil {
		return normalized.Event{}, false, err
	}
	for _, event := range snap.Events {
		if event.EventID == eventID {
			return event, true, nil
		}
	}
	return normalized.Event{}, false, nil
}

func (s *DBStore) GetDeviceInventoryDetail(ctx context.Context, id string) (InventoryDetail, bool, error) {
	return s.pg.GetDeviceInventoryDetail(ctx, id)
}
func (s *DBStore) ListEndpointObservations(ctx context.Context, id string, q EndpointObservationQuery) (EndpointObservationPage, error) {
	return s.pg.ListEndpointObservations(ctx, id, q)
}

func (s *PostgresStore) GetDeviceInventoryDetail(ctx context.Context, id string) (InventoryDetail, bool, error) {
	endpoint, found, err := s.getEndpointEntity(ctx, id)
	if err != nil || !found {
		return InventoryDetail{}, found, err
	}
	result := InventoryDetail{Profile: EndpointIdentityProfile{EndpointID: id, Endpoint: endpoint, Accounts: []string{}, Sessions: []AccountSession{}, IPHistory: []IdentityIPMACHistory{}, AccessHistory: []IdentityAccessHistory{}}, Associations: []InventoryAssociation{}}
	result.Profile.FirstSeen = endpoint.FirstSeen
	result.Profile.LastSeen = endpoint.LastSeen
	// Endpoint-local coverage; global backfill must not block prepared details.
	var raw []byte
	var at time.Time
	err = s.db.QueryRowContext(ctx, `SELECT list_item,updated_at FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, id).Scan(&raw, &at)
	if err == sql.ErrNoRows {
		result.State = InventoryProjectionState{Updating: true}
		return result, true, nil
	}
	if err != nil {
		return result, true, err
	}
	var item EndpointDeviceInventory
	if err = json.Unmarshal(raw, &item); err != nil {
		return result, true, err
	}
	result.Profile.Recognition = &item
	result.Profile.LastSeen = item.LastSeen
	item.EntityRole = endpoint.EntityRole
	item.RegistrationStatus = endpoint.RegistrationStatus
	item.MergeStatus = endpoint.MergeStatus
	item.Accounts = []string{}
	item.IPs = []string{}
	item.AccessIDs = []string{}
	result.Profile.DeviceName = item.DeviceName
	result.Profile.Accounts = append([]string{}, item.CurrentAccountCandidates...)
	global, err := inventoryProjectionState(ctx, s.db)
	if err != nil {
		return result, true, err
	}
	result.State.Complete = global.Complete
	result.State.Error = global.Error
	result.State.AsOf = at.UTC().Format(time.RFC3339Nano)
	if err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1 AND processed_generation<dirty_generation)`, id).Scan(&result.State.Updating); err != nil {
		return result, true, err
	}
	result.State.Updating = result.State.Updating || global.Updating
	rows, err := s.db.QueryContext(ctx, `SELECT kind,value,source,first_seen,last_seen,observation_count,session_count,confidence,event_id FROM endpoint_inventory_associations WHERE endpoint_id=$1 ORDER BY last_seen DESC,kind,value,source LIMIT 20`, id)
	if err != nil {
		return result, true, err
	}
	for rows.Next() {
		var a InventoryAssociation
		var first, last time.Time
		if err = rows.Scan(&a.Kind, &a.Value, &a.Source, &first, &last, &a.ObservationCount, &a.SessionCount, &a.Confidence, &a.EventID); err != nil {
			rows.Close()
			return result, true, err
		}
		a.FirstSeen = first.UTC().Format(time.RFC3339Nano)
		a.LastSeen = last.UTC().Format(time.RFC3339Nano)
		result.Associations = append(result.Associations, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, true, err
	}
	result.AssociationCounts = map[string]int{}
	rows, err = s.db.QueryContext(ctx, `SELECT kind,count(DISTINCT value) FROM endpoint_inventory_associations WHERE endpoint_id=$1 GROUP BY kind`, id)
	if err != nil {
		return result, true, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var count int
		if err = rows.Scan(&kind, &count); err != nil {
			return result, true, err
		}
		result.AssociationCounts[kind] = count
	}
	return result, true, rows.Err()
}

type observationCursor struct {
	Signature string `json:"s"`
	At        string `json:"t"`
	Key       string `json:"k"`
	AsOf      string `json:"a"`
}

func validateObservationQuery(q *EndpointObservationQuery) error {
	switch q.Kind {
	case "account", "ip", "access":
	default:
		return fmt.Errorf("kind must be account, ip or access")
	}
	if q.Limit == 0 {
		q.Limit = 20
	}
	if q.Limit < 1 || q.Limit > 100 {
		return fmt.Errorf("limit must be between 1 and 100")
	}
	if len(q.Value) > 256 || len(q.Source) > 128 || len(q.Cursor) > 2048 {
		return fmt.Errorf("observation filter too long")
	}
	if q.Kind == "ip" && q.Value != "" {
		ip := net.ParseIP(q.Value)
		if ip == nil {
			return fmt.Errorf("invalid exact IP value")
		}
		q.Value = ip.String()
	}
	for _, v := range []string{q.Start, q.End} {
		if v != "" {
			if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
				return fmt.Errorf("invalid observation time")
			}
		}
	}
	if q.Start != "" && q.End != "" {
		a, _ := time.Parse(time.RFC3339Nano, q.Start)
		b, _ := time.Parse(time.RFC3339Nano, q.End)
		if a.After(b) {
			return fmt.Errorf("start must not exceed end")
		}
	}
	return nil
}
func observationSignature(id string, q EndpointObservationQuery) string {
	raw, _ := json.Marshal([]string{id, q.Kind, q.Value, q.Source, q.Start, q.End})
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum)
}
func observationPosition(id string, q EndpointObservationQuery) (observationCursor, error) {
	c := observationCursor{Signature: observationSignature(id, q), AsOf: time.Now().UTC().Format(time.RFC3339Nano)}
	if q.Cursor == "" {
		return c, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
	if err != nil {
		return c, fmt.Errorf("invalid cursor")
	}
	var decoded observationCursor
	if json.Unmarshal(raw, &decoded) != nil || decoded.Signature != c.Signature {
		return c, fmt.Errorf("cursor does not match endpoint and filters")
	}
	if _, err = time.Parse(time.RFC3339Nano, decoded.At); err != nil {
		return c, fmt.Errorf("invalid cursor time")
	}
	if _, err = time.Parse(time.RFC3339Nano, decoded.AsOf); err != nil {
		return c, fmt.Errorf("invalid cursor snapshot")
	}
	return decoded, nil
}
func ValidateEndpointObservationQuery(id string, q *EndpointObservationQuery) error {
	if err := validateObservationQuery(q); err != nil {
		return err
	}
	_, err := observationPosition(id, *q)
	return err
}

func (s *PostgresStore) ListEndpointObservations(ctx context.Context, id string, q EndpointObservationQuery) (EndpointObservationPage, error) {
	result := EndpointObservationPage{Items: []EndpointObservation{}}
	if err := validateObservationQuery(&q); err != nil {
		return result, err
	}
	c, err := observationPosition(id, q)
	if err != nil {
		return result, err
	}
	var at time.Time
	err = s.db.QueryRowContext(ctx, `SELECT updated_at FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, id).Scan(&at)
	if err == sql.ErrNoRows {
		return result, ErrInventoryNotReady
	}
	if err != nil {
		return result, err
	}
	result.State = InventoryProjectionState{Complete: true, AsOf: at.UTC().Format(time.RFC3339Nano)}
	global, err := inventoryProjectionState(ctx, s.db)
	if err != nil {
		return result, err
	}
	if !global.Complete {
		return result, ErrInventoryNotReady
	}
	result.State.Error = global.Error
	if err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1 AND processed_generation<dirty_generation)`, id).Scan(&result.State.Updating); err != nil {
		return result, err
	}
	result.State.Updating = result.State.Updating || global.Updating
	// Every branch is endpoint-bounded. Stable keyset cursor replaces LIMIT 500
	// and frontend slicing. Sessions provide explicit intervals, observations do not.
	sqlText := `WITH facts AS (
 SELECT record_id,kind,value,source,observed_at,confidence,event_id,NULL::timestamptz started_at,NULL::timestamptz ended_at
 FROM endpoint_inventory_observation_facts WHERE endpoint_id=$1 AND kind=$2
 ), observations AS (
 SELECT * FROM facts UNION ALL
 SELECT 'session:'||jsonb_build_array(source,session_id,host(ip))::text,$2,
 CASE $2 WHEN 'account' THEN account_id WHEN 'ip' THEN host(ip) ELSE access_id END,
 source,confirmed_at,confidence,''::text,started_at,ended_at FROM endpoint_inventory_sessions WHERE endpoint_id=$1 AND interval_explicit
 ) SELECT record_id,kind,value,source,observed_at,confidence,event_id,started_at,ended_at FROM observations
 WHERE value<>'' AND ($3='' OR value=$3) AND ($4='' OR source=$4)
 AND ($5::timestamptz IS NULL OR observed_at>=$5) AND ($6::timestamptz IS NULL OR observed_at<=$6) AND observed_at<=$7
 AND ($8::timestamptz IS NULL OR (observed_at,record_id)<($8::timestamptz,$9)) ORDER BY observed_at DESC,record_id DESC LIMIT $10`
	nullable := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	rows, err := s.db.QueryContext(ctx, sqlText, id, q.Kind, q.Value, q.Source, nullable(q.Start), nullable(q.End), c.AsOf, nullable(c.At), c.Key, q.Limit+1)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var v EndpointObservation
		var stamp time.Time
		var start, end sql.NullTime
		if err = rows.Scan(&v.RecordID, &v.Kind, &v.Value, &v.Source, &stamp, &v.Confidence, &v.EventID, &start, &end); err != nil {
			return result, err
		}
		if len(result.Items) == q.Limit {
			last := result.Items[len(result.Items)-1]
			c.At = last.ObservedAt
			c.Key = last.RecordID
			raw, _ := json.Marshal(c)
			result.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
			continue
		}
		v.ObservedAt = stamp.UTC().Format(time.RFC3339Nano)
		v.StartedAt = nullTimeText(start)
		v.EndedAt = nullTimeText(end)
		v.EvidenceState = "not_checked"
		if stamp.Before(time.Now().Add(-7 * 24 * time.Hour)) {
			v.EvidenceState = "outside_retention"
		}
		if strings.HasPrefix(v.RecordID, "session:") {
			v.EvidenceState = "retained_session"
			var key [3]string
			if json.Unmarshal([]byte(strings.TrimPrefix(v.RecordID, "session:")), &key) == nil {
				v.SessionID = key[1]
			}
			v.EvidenceURL = "/endpoints/" + url.PathEscape(id) + "/observations/" + url.PathEscape(v.RecordID) + "/evidence"
		}
		if strings.HasPrefix(v.RecordID, "snapshot:") {
			v.EvidenceState = "snapshot_reference"
			v.EvidenceURL = "/endpoints/" + url.PathEscape(id) + "/observations/" + url.PathEscape(v.RecordID) + "/evidence"
		}
		result.Items = append(result.Items, v)
	}
	return result, rows.Err()
}
