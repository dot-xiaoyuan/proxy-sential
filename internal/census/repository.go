package census

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

var priorityTypes = []string{"printer", "camera", "recorder", "access_control", "voip_phone"}

type Query struct {
	HardwareV2     bool
	SensorID       string
	CampusID       string
	AccessDomain   string
	VLAN           string
	VRF            string
	Window         time.Duration
	Kind           string
	TerminalStatus string
	Limit          int
	Cursor         string
}

func (q Query) normalized() (Query, error) {
	if q.SensorID == "" {
		return q, fmt.Errorf("sensor_id is required")
	}
	if q.Window == 0 {
		q.Window = 24 * time.Hour
	}
	if q.Window != 24*time.Hour && q.Window != 7*24*time.Hour && q.Window != 30*24*time.Hour {
		return q, fmt.Errorf("invalid census window")
	}
	if q.Kind == "" {
		q.Kind = "ip"
	}
	if q.Kind != "ip" && q.Kind != "mac" && q.Kind != "binding" && q.Kind != "terminal" {
		return q, fmt.Errorf("invalid census kind")
	}
	if q.TerminalStatus != "" && (q.Kind != "terminal" || q.TerminalStatus != "identified" && q.TerminalStatus != "candidate" && q.TerminalStatus != "conflict" && q.TerminalStatus != "expired") {
		return q, fmt.Errorf("invalid census terminal status")
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 200 {
		return q, fmt.Errorf("census page exceeds 200")
	}
	return q, nil
}

type Scope struct {
	SensorID     string `json:"sensor_id"`
	CampusID     string `json:"campus_id,omitempty"`
	AccessDomain string `json:"access_domain,omitempty"`
	VLAN         string `json:"vlan,omitempty"`
	VRF          string `json:"vrf,omitempty"`
}

func (q Query) scope() Scope {
	return Scope{SensorID: q.SensorID, CampusID: q.CampusID, AccessDomain: q.AccessDomain, VLAN: q.VLAN, VRF: q.VRF}
}

type TypeCount struct {
	DeviceType string `json:"device_type"`
	Identified int64  `json:"identified"`
	Candidate  int64  `json:"candidate"`
	Conflict   int64  `json:"conflict"`
	Expired    int64  `json:"expired"`
}

type Summary struct {
	MetricVersion       string      `json:"metric_version"`
	Scope               Scope       `json:"scope"`
	Window              string      `json:"window"`
	Status              string      `json:"status"`
	AsOf                *time.Time  `json:"as_of,omitempty"`
	AvailableFrom       *time.Time  `json:"available_from,omitempty"`
	LastSuccessAt       *time.Time  `json:"last_success_at,omitempty"`
	OldestPendingAt     *time.Time  `json:"oldest_pending_at,omitempty"`
	FailedBatches       int64       `json:"failed_batches"`
	LastBatchRows       int         `json:"last_batch_rows"`
	LastBatchMS         int         `json:"last_batch_ms"`
	ScopeVersion        string      `json:"scope_version,omitempty"`
	ObservedIPs         int64       `json:"observed_ips"`
	ObservedIPv4        int64       `json:"observed_ipv4"`
	ObservedIPv6        int64       `json:"observed_ipv6"`
	ObservedMACs        int64       `json:"observed_macs"`
	RandomMACs          int64       `json:"random_macs"`
	IncompleteScope     int64       `json:"incomplete_scope"`
	ActiveBindings      int64       `json:"active_bindings"`
	IdentifiedTerminals int64       `json:"identified_terminals"`
	TerminalCandidates  int64       `json:"terminal_candidates"`
	TerminalConflicts   int64       `json:"terminal_conflicts"`
	TerminalExpired     int64       `json:"terminal_expired"`
	ManuallyVerified    int64       `json:"manually_verified"`
	Types               []TypeCount `json:"types"`
}

type Reader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type Repository struct {
	DB         Reader
	HardwareV2 bool
}

func scopeWhere(q Query, alias string, starting int) (string, []any) {
	values := []struct{ column, value string }{{"sensor_id", q.SensorID}, {"campus_id", q.CampusID}, {"access_domain", q.AccessDomain}, {"vlan", q.VLAN}, {"vrf", q.VRF}}
	conditions := []string{}
	args := []any{}
	for _, entry := range values {
		if entry.value == "" {
			continue
		}
		args = append(args, entry.value)
		conditions = append(conditions, fmt.Sprintf("%s.%s=$%d", alias, entry.column, starting+len(args)-1))
	}
	return strings.Join(conditions, " AND "), args
}

// Summary reads only current projections. Missing runtime state is explicit,
// never represented as a successful zero-device inventory.
func (r Repository) GetSummary(ctx context.Context, query Query) (Summary, error) {
	query.HardwareV2 = r.HardwareV2
	q, err := query.normalized()
	if err != nil {
		return Summary{}, err
	}
	result := Summary{MetricVersion: "passive-census/v1", Scope: q.scope(), Window: q.Window.String(), Status: "initializing", Types: []TypeCount{}}
	if r.HardwareV2 {
		result.MetricVersion = "passive-census/v2"
	}
	var available, source, success, pending sql.NullTime
	var scopeVersion string
	err = r.DB.QueryRowContext(ctx, `SELECT available_from,last_source_at,last_success_at,oldest_pending_at,failed_batches,scope_version,last_batch_rows,last_batch_ms FROM passive_census_runtime WHERE sensor_id=$1`, q.SensorID).Scan(&available, &source, &success, &pending, &result.FailedBatches, &scopeVersion, &result.LastBatchRows, &result.LastBatchMS)
	if err == sql.ErrNoRows {
		return result, nil
	}
	if err != nil {
		return Summary{}, err
	}
	result.ScopeVersion = scopeVersion
	if available.Valid {
		result.AvailableFrom = &available.Time
	}
	if source.Valid {
		result.AsOf = &source.Time
	}
	if success.Valid {
		result.LastSuccessAt = &success.Time
	}
	if pending.Valid {
		result.OldestPendingAt = &pending.Time
	}
	if !source.Valid {
		return result, nil
	}
	cutoff := source.Time.Add(-q.Window)
	where, scopeArgs := scopeWhere(q, "i", 2)
	args := append([]any{cutoff}, scopeArgs...)
	err = r.DB.QueryRowContext(ctx, `SELECT
 count(*) FILTER(WHERE kind='ip'),count(*) FILTER(WHERE kind='ip' AND ip_family=4),count(*) FILTER(WHERE kind='ip' AND ip_family=6),
 count(*) FILTER(WHERE kind='mac'),count(*) FILTER(WHERE kind='mac' AND random_mac),
 count(*) FILTER(WHERE campus_id='' OR access_domain='' OR vlan='')
 FROM passive_census_identifier_current i WHERE i.last_seen>=$1 AND `+where, args...).Scan(&result.ObservedIPs, &result.ObservedIPv4, &result.ObservedIPv6, &result.ObservedMACs, &result.RandomMACs, &result.IncompleteScope)
	if err != nil {
		return Summary{}, err
	}
	// Only unambiguous, unwithdrawn pairs with evidence still valid count.
	bindingsWhere, bindingScopeArgs := projectionScopeWhere(q, "b", 2)
	bindingArgs := append([]any{cutoff}, bindingScopeArgs...)
	err = r.DB.QueryRowContext(ctx, `SELECT count(*) FROM passive_census_binding_current b
 WHERE b.observed_at>=$1 AND b.valid_until>now() AND NOT b.withdrawn AND `+bindingsWhere+`
 AND NOT EXISTS(SELECT 1 FROM passive_census_binding_current peer WHERE peer.scope_key=b.scope_key AND peer.ip=b.ip AND peer.mac<>b.mac AND peer.valid_until>now() AND NOT peer.withdrawn)`, bindingArgs...).Scan(&result.ActiveBindings)
	if err != nil {
		return Summary{}, err
	}
	terminalWhere, terminalScopeArgs := scopeWhere(q, "t", 2)
	terminalArgs := append([]any{cutoff}, terminalScopeArgs...)
	rows, err := r.DB.QueryContext(ctx, `SELECT effective_type,`+terminalStatusSQL(r.HardwareV2)+`,count(*) FROM `+terminalProjectionSQL(r.HardwareV2)+` t
 JOIN passive_census_identifier_current m ON m.scope_key=t.scope_key AND m.kind='mac' AND m.value=t.mac AND m.last_seen>=$1
 WHERE t.last_seen>=$1 AND `+terminalWhere+`
 AND effective_type=ANY(`+censusPriorityArraySQL(r.HardwareV2)+`)
 GROUP BY effective_type,`+terminalStatusSQL(r.HardwareV2), terminalArgs...)
	if err != nil {
		return Summary{}, err
	}
	defer rows.Close()
	byType := map[string]*TypeCount{}
	for _, name := range censusPriorityTypes(r.HardwareV2) {
		byType[name] = &TypeCount{DeviceType: name}
	}
	for rows.Next() {
		var kind, state string
		var count int64
		if err = rows.Scan(&kind, &state, &count); err != nil {
			return Summary{}, err
		}
		item := byType[kind]
		if item == nil {
			continue
		}
		switch state {
		case "identified":
			item.Identified += count
			result.IdentifiedTerminals += count
		case "candidate":
			item.Candidate += count
			result.TerminalCandidates += count
		case "conflict":
			item.Conflict += count
			result.TerminalConflicts += count
		case "expired":
			item.Expired += count
			result.TerminalExpired += count
		}
	}
	if err = rows.Err(); err != nil {
		return Summary{}, err
	}
	for _, name := range censusPriorityTypes(r.HardwareV2) {
		result.Types = append(result.Types, *byType[name])
	}
	result.Status = "ready"
	if !available.Valid || available.Time.After(cutoff) || pending.Valid {
		result.Status = "partial"
	}
	if success.Valid && time.Since(success.Time) > 10*time.Minute {
		result.Status = "delayed"
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_CENSUS_SITE_CIDRS")); raw != "" {
		prefixes := []netip.Prefix{}
		for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }) {
			prefix, parseErr := netip.ParsePrefix(item)
			if parseErr != nil {
				result.Status = "scope_changed"
				return result, nil
			}
			prefixes = append(prefixes, prefix)
		}
		if scopeVersion != ScopeVersion(prefixes) {
			result.Status = "scope_changed"
		}
	} else {
		result.Status = "scope_changed"
	}
	return result, nil
}

func projectionScopeWhere(q Query, alias string, starting int) (string, []any) {
	// The terminal projection stores the exact scope key; derive it only when
	// the complete scope is selected, otherwise keep the sensor boundary.
	args := []any{q.SensorID}
	conditions := []string{fmt.Sprintf("%s.scope_key IN (SELECT DISTINCT scope_key FROM passive_census_identifier_current WHERE sensor_id=$%d)", alias, starting)}
	if q.CampusID != "" || q.AccessDomain != "" || q.VLAN != "" || q.VRF != "" {
		where, extra := scopeWhere(q, "i", starting)
		conditions = []string{alias + ".scope_key IN (SELECT DISTINCT i.scope_key FROM passive_census_identifier_current i WHERE " + where + ")"}
		args = extra
	}
	return strings.Join(conditions, " AND "), args
}

type Row struct {
	HardwareTypeStatus   string    `json:"hardware_type_status,omitempty"`
	ActivityStatus       string    `json:"activity_status,omitempty"`
	Kind                 string    `json:"kind"`
	ScopeKey             string    `json:"scope_key"`
	SensorID             string    `json:"sensor_id"`
	CampusID             string    `json:"campus_id"`
	AccessDomain         string    `json:"access_domain"`
	VLAN                 string    `json:"vlan"`
	VRF                  string    `json:"vrf"`
	Value                string    `json:"value"`
	IPFamily             int       `json:"ip_family,omitempty"`
	RandomMAC            bool      `json:"random_mac,omitempty"`
	FirstSeen            time.Time `json:"first_seen"`
	LastSeen             time.Time `json:"last_seen"`
	LastEventID          string    `json:"last_event_id,omitempty"`
	Source               string    `json:"source,omitempty"`
	EffectiveType        string    `json:"effective_type,omitempty"`
	ClassificationStatus string    `json:"classification_status,omitempty"`
	DeviceKey            string    `json:"device_key,omitempty"`
	IP                   string    `json:"ip,omitempty"`
	MAC                  string    `json:"mac,omitempty"`
}

type Page struct {
	Items      []Row  `json:"items"`
	NextCursor string `json:"next_cursor"`
	HasMore    bool   `json:"has_more"`
}

type pageCursor struct {
	Signature string `json:"signature"`
	ScopeKey  string `json:"scope_key"`
	Value     string `json:"value"`
}

func querySignature(q Query) string {
	raw, _ := json.Marshal([]any{q.SensorID, q.CampusID, q.AccessDomain, q.VLAN, q.VRF, q.Window.String(), q.Kind, q.TerminalStatus, q.HardwareV2})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func decodeCursor(q Query) (pageCursor, error) {
	if q.Cursor == "" {
		return pageCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
	var cursor pageCursor
	if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Signature != querySignature(q) || cursor.ScopeKey == "" || cursor.Value == "" {
		return pageCursor{}, fmt.Errorf("invalid census cursor")
	}
	return cursor, nil
}

func (r Repository) GetPage(ctx context.Context, query Query) (Page, error) {
	query.HardwareV2 = r.HardwareV2
	q, err := query.normalized()
	if err != nil {
		return Page{}, err
	}
	cursor, err := decodeCursor(q)
	if err != nil {
		return Page{}, err
	}
	var asOf sql.NullTime
	if err = r.DB.QueryRowContext(ctx, `SELECT last_source_at FROM passive_census_runtime WHERE sensor_id=$1`, q.SensorID).Scan(&asOf); err == sql.ErrNoRows {
		return Page{Items: []Row{}}, nil
	} else if err != nil {
		return Page{}, err
	}
	if !asOf.Valid {
		return Page{Items: []Row{}}, nil
	}
	if q.Kind == "terminal" {
		return r.getTerminalPage(ctx, q, cursor, asOf.Time)
	}
	if q.Kind == "binding" {
		return r.getBindingPage(ctx, q, cursor, asOf.Time)
	}
	where, scopeArgs := scopeWhere(q, "i", 3)
	args := []any{asOf.Time.Add(-q.Window), q.Kind}
	args = append(args, scopeArgs...)
	if cursor.ScopeKey != "" {
		args = append(args, cursor.ScopeKey, cursor.Value)
		where += fmt.Sprintf(" AND (i.scope_key,i.value)>($%d,$%d)", len(args)-1, len(args))
	}
	args = append(args, q.Limit+1)
	rows, err := r.DB.QueryContext(ctx, `SELECT i.scope_key,i.sensor_id,i.campus_id,i.access_domain,i.vlan,i.vrf,i.kind,i.value,i.ip_family,i.random_mac,i.first_seen,i.last_seen,i.last_event_id,i.last_source
 FROM passive_census_identifier_current i WHERE i.last_seen>=$1 AND i.kind=$2 AND `+where+` ORDER BY i.scope_key,i.value LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	page := Page{Items: []Row{}}
	for rows.Next() {
		var item Row
		if err = rows.Scan(&item.ScopeKey, &item.SensorID, &item.CampusID, &item.AccessDomain, &item.VLAN, &item.VRF, &item.Kind, &item.Value, &item.IPFamily, &item.RandomMAC, &item.FirstSeen, &item.LastSeen, &item.LastEventID, &item.Source); err != nil {
			return Page{}, err
		}
		page.Items = append(page.Items, item)
	}
	if err = rows.Err(); err != nil {
		return Page{}, err
	}
	page.HasMore = len(page.Items) > q.Limit
	if page.HasMore {
		page.Items = page.Items[:q.Limit]
		last := page.Items[len(page.Items)-1]
		raw, _ := json.Marshal(pageCursor{Signature: querySignature(q), ScopeKey: last.ScopeKey, Value: last.Value})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}

func (r Repository) getBindingPage(ctx context.Context, q Query, cursor pageCursor, asOf time.Time) (Page, error) {
	where, scopeArgs := projectionScopeWhere(q, "b", 2)
	args := append([]any{asOf.Add(-q.Window)}, scopeArgs...)
	if cursor.ScopeKey != "" {
		pair := strings.SplitN(cursor.Value, "|", 2)
		if len(pair) != 2 {
			return Page{}, fmt.Errorf("invalid binding cursor")
		}
		args = append(args, cursor.ScopeKey, pair[0], pair[1])
		where += fmt.Sprintf(" AND (b.scope_key,b.ip,b.mac)>($%d,$%d,$%d)", len(args)-2, len(args)-1, len(args))
	}
	args = append(args, q.Limit+1)
	rows, err := r.DB.QueryContext(ctx, `SELECT b.scope_key,i.sensor_id,i.campus_id,i.access_domain,i.vlan,i.vrf,b.ip,b.mac,b.observed_at,b.evidence_event_id,b.source
 FROM passive_census_binding_current b JOIN passive_census_identifier_current i ON i.scope_key=b.scope_key AND i.kind='ip' AND i.value=b.ip
 WHERE b.observed_at>=$1 AND b.valid_until>now() AND NOT b.withdrawn AND `+where+`
 AND NOT EXISTS(SELECT 1 FROM passive_census_binding_current peer WHERE peer.scope_key=b.scope_key AND peer.ip=b.ip AND peer.mac<>b.mac AND peer.valid_until>now() AND NOT peer.withdrawn)
 ORDER BY b.scope_key,b.ip,b.mac LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	page := Page{Items: []Row{}}
	for rows.Next() {
		var item Row
		if err = rows.Scan(&item.ScopeKey, &item.SensorID, &item.CampusID, &item.AccessDomain, &item.VLAN, &item.VRF, &item.IP, &item.MAC, &item.LastSeen, &item.LastEventID, &item.Source); err != nil {
			return Page{}, err
		}
		item.FirstSeen = item.LastSeen
		item.Kind, item.Value = "binding", item.IP+"|"+item.MAC
		page.Items = append(page.Items, item)
	}
	if err = rows.Err(); err != nil {
		return Page{}, err
	}
	page.HasMore = len(page.Items) > q.Limit
	if page.HasMore {
		page.Items = page.Items[:q.Limit]
		last := page.Items[len(page.Items)-1]
		raw, _ := json.Marshal(pageCursor{Signature: querySignature(q), ScopeKey: last.ScopeKey, Value: last.Value})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}

func (r Repository) getTerminalPage(ctx context.Context, q Query, cursor pageCursor, asOf time.Time) (Page, error) {
	where, scopeArgs := scopeWhere(q, "t", 2)
	args := append([]any{asOf.Add(-q.Window)}, scopeArgs...)
	if q.TerminalStatus != "" {
		args = append(args, q.TerminalStatus)
		where += fmt.Sprintf(" AND ("+terminalStatusSQL(r.HardwareV2)+")=$%d", len(args))
	}
	if cursor.ScopeKey != "" {
		args = append(args, cursor.ScopeKey, cursor.Value)
		where += fmt.Sprintf(" AND (t.scope_key,t.identity_key)>($%d,$%d)", len(args)-1, len(args))
	}
	args = append(args, q.Limit+1)
	extra := ""
	if r.HardwareV2 {
		extra = ",CASE WHEN t.effective_until>now() THEN 'active' ELSE 'stale' END"
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT t.scope_key,t.sensor_id,t.campus_id,t.access_domain,t.vlan,t.vrf,t.identity_key,t.device_key,t.mac,t.effective_type,
 `+terminalStatusSQL(r.HardwareV2)+`,t.first_seen,t.last_seen`+extra+`
 FROM `+terminalProjectionSQL(r.HardwareV2)+` t
 JOIN passive_census_identifier_current m ON m.scope_key=t.scope_key AND m.kind='mac' AND m.value=t.mac AND m.last_seen>=$1
 WHERE t.last_seen>=$1 AND `+where+`
 AND t.effective_type=ANY(`+censusPriorityArraySQL(r.HardwareV2)+`)
 ORDER BY t.scope_key,t.identity_key LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	page := Page{Items: []Row{}}
	for rows.Next() {
		var item Row
		dest := []any{&item.ScopeKey, &item.SensorID, &item.CampusID, &item.AccessDomain, &item.VLAN, &item.VRF, &item.Value, &item.DeviceKey, &item.MAC, &item.EffectiveType, &item.ClassificationStatus, &item.FirstSeen, &item.LastSeen}
		if r.HardwareV2 {
			dest = append(dest, &item.ActivityStatus)
		}
		if err = rows.Scan(dest...); err != nil {
			return Page{}, err
		}
		if r.HardwareV2 {
			item.HardwareTypeStatus = item.ClassificationStatus
			if item.ClassificationStatus == "expired" {
				item.HardwareTypeStatus = "revoked"
			}
		}
		item.Kind = "terminal"
		page.Items = append(page.Items, item)
	}
	if err = rows.Err(); err != nil {
		return Page{}, err
	}
	page.HasMore = len(page.Items) > q.Limit
	if page.HasMore {
		page.Items = page.Items[:q.Limit]
		last := page.Items[len(page.Items)-1]
		raw, _ := json.Marshal(pageCursor{Signature: querySignature(q), ScopeKey: last.ScopeKey, Value: last.Value})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}
