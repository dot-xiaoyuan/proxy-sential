package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"proxy-sentinel/internal/normalized"
	"sort"
	"strings"
	"sync"
	"time"
)

type Repository struct {
	DB          *sql.DB
	Archive     func(context.Context, []normalized.Event) error
	DeviceCache *DeviceCache
}

type deviceCacheEntry struct {
	expires time.Time
	items   []DeviceView
}

type DeviceCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]deviceCacheEntry
}

func NewDeviceCache(ttl time.Duration) *DeviceCache {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	return &DeviceCache{ttl: ttl, entries: map[string]deviceCacheEntry{}}
}

func (c *DeviceCache) load(key string, loader func() ([]DeviceView, error)) ([]DeviceView, error) {
	if c == nil {
		return loader()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if entry, ok := c.entries[key]; ok && entry.expires.After(now) {
		return append([]DeviceView(nil), entry.items...), nil
	}
	items, err := loader()
	if err != nil {
		return nil, err
	}
	for existingKey, entry := range c.entries {
		if !entry.expires.After(now) {
			delete(c.entries, existingKey)
		}
	}
	c.entries[key] = deviceCacheEntry{expires: now.Add(c.ttl), items: append([]DeviceView(nil), items...)}
	return append([]DeviceView(nil), items...), nil
}

type Task struct {
	ID              string          `json:"id"`
	SourceID        string          `json:"source_id"`
	Node            string          `json:"node"`
	Kind            string          `json:"kind"`
	Status          string          `json:"status"`
	Version         int             `json:"config_version"`
	Config          json.RawMessage `json:"config"`
	EncryptedSecret string          `json:"-"`
	CreatedAt       time.Time       `json:"created_at"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           string          `json:"error,omitempty"`
	CancelRequested bool            `json:"cancel_requested"`
}

func (r Repository) SaveSnapshot(ctx context.Context, s Snapshot) error {
	for _, e := range s.Events {
		if _, err := FromEvent(e); err != nil {
			return err
		}
	}
	if r.Archive != nil && len(s.Events) > 0 {
		if err := r.Archive(ctx, s.Events); err != nil {
			return err
		}
	}

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	raw, _ := json.Marshal(s)
	if _, err = tx.ExecContext(ctx, `INSERT INTO discovery_snapshots(id,source_id,config_version,observed_at,data) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, s.ID, s.SourceID, s.ConfigVersion, s.At, raw); err != nil {
		return err
	}
	for _, e := range s.Events {
		o, err := FromEvent(e)
		if err != nil {
			return err
		}
		if o.Withdrawn && o.Origin == "ssdp" {
			if _, err = tx.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1) WHERE source_id=$2 AND origin='ssdp' AND observed_at<=$1 AND data->>'ip'=$3 AND data->'evidence'->'payload'->>'service_type'=$4 AND data->'evidence'->'payload'->>'usn'=$5 AND coalesce(data->>'site','')=$6 AND coalesce(data->>'domain','')=$7 AND coalesce(data->>'vlan','')=$8`, o.ObservedAt, o.SourceID, o.IP, str(o.Evidence.Payload, "service_type"), str(o.Evidence.Payload, "usn"), o.Site, o.Domain, o.VLAN); err != nil {
				return err
			}
		}
		if o.Withdrawn && o.Origin == "dns_sd" {
			if _, err = tx.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1) WHERE source_id=$2 AND origin='dns_sd' AND observed_at<=$1 AND data->'evidence'->'payload'->>'service_target'=$3 AND data->'evidence'->'payload'->>'service_instance'=$4 AND coalesce(data->>'site','')=$5 AND coalesce(data->>'domain','')=$6 AND coalesce(data->>'vlan','')=$7`, o.ObservedAt, o.SourceID, str(o.Evidence.Payload, "service_target"), str(o.Evidence.Payload, "service_instance"), o.Site, o.Domain, o.VLAN); err != nil {
				return err
			}
		}
		if o.Origin == "neighbor" && o.IP != "" && o.MAC != "" {
			if _, err = tx.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1) WHERE origin='neighbor' AND observed_at<$1 AND source_id=$2 AND data->>'ip'=$3 AND data->>'mac'<>$4 AND coalesce(data->>'site','')=$5 AND coalesce(data->>'domain','')=$6 AND coalesce(data->>'vlan','')=$7 AND coalesce(data->>'vrf','')=$8`, o.ObservedAt, o.SourceID, o.IP, o.MAC, o.Site, o.Domain, o.VLAN, o.VRF); err != nil {
				return err
			}
		}
		b, _ := json.Marshal(o)
		if _, err = tx.ExecContext(ctx, `INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, o.ID, o.Key(), o.SourceID, o.Origin, o.ObservedAt, o.ValidUntil, o.Withdrawn, b); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (r Repository) EnqueuePoll(ctx context.Context, id, source string) error {
	result, err := r.DB.ExecContext(ctx, `INSERT INTO discovery_tasks(id,source_id,node,kind,config_version,config,encrypted_secret) SELECT $1,id,node,'snmp',config_version,config,encrypted_secret FROM discovery_sources WHERE id=$2 ON CONFLICT DO NOTHING`, id, source)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("source missing or already queued")
	}
	return nil
}
func (r Repository) Claim(ctx context.Context, node string) (Task, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return Task{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "discovery-node:"+node); err != nil {
		return Task{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE discovery_tasks SET status=CASE WHEN cancel_requested THEN 'cancelled' WHEN attempt>=3 THEN 'failed' ELSE 'pending' END,error='worker lease expired',lease_until=NULL WHERE node=$1 AND status='running' AND lease_until<now()`, node)
	if err != nil {
		return Task{}, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM discovery_tasks WHERE node=$1 AND status='running'`, node).Scan(&active); err != nil {
		return Task{}, err
	}
	if active >= 3 {
		return Task{}, sql.ErrNoRows
	}
	var t Task
	err = tx.QueryRowContext(ctx, `UPDATE discovery_tasks SET status='running',attempt=attempt+1,started_at=now(),lease_until=now()+interval '2 hours' WHERE id=(SELECT id FROM discovery_tasks WHERE node=$1 AND status='pending' AND NOT cancel_requested AND ((kind='snmp' AND (SELECT count(*) FROM discovery_tasks a WHERE a.node=$1 AND a.status='running' AND a.kind='snmp')<2) OR (kind='scan' AND NOT EXISTS(SELECT 1 FROM discovery_tasks a WHERE a.node=$1 AND a.status='running' AND a.kind='scan'))) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,coalesce(source_id,''),node,kind,status,config_version,config,encrypted_secret,created_at`, node).Scan(&t.ID, &t.SourceID, &t.Node, &t.Kind, &t.Status, &t.Version, &t.Config, &t.EncryptedSecret, &t.CreatedAt)
	if err != nil {
		return t, err
	}
	return t, tx.Commit()
}
func (r Repository) Schedule(ctx context.Context) error {
	_, err := r.DB.ExecContext(ctx, `WITH due AS (SELECT * FROM discovery_sources WHERE enabled AND next_poll<=now() FOR UPDATE SKIP LOCKED), queued AS (INSERT INTO discovery_tasks(id,source_id,node,kind,config_version,config,encrypted_secret) SELECT 'poll-'||md5(id||clock_timestamp()::text),id,node,'snmp',config_version,config,encrypted_secret FROM due ON CONFLICT DO NOTHING RETURNING source_id) UPDATE discovery_sources SET next_poll=now()+make_interval(secs=>greatest(60,coalesce((config->>'interval_seconds')::int,300))) WHERE id IN (SELECT source_id FROM queued)`)
	return err
}
func (r Repository) Finish(ctx context.Context, t Task, s Snapshot, runErr error) error {
	status, message := "complete", ""
	if runErr != nil {
		status = "failed"
		message = "采集失败，请核对连接、权限及协议支持"
	}
	for _, v := range s.Tables {
		if !v.Complete && runErr == nil {
			status = "partial"
		}
	}
	b, _ := json.Marshal(s)
	_, err := r.DB.ExecContext(ctx, `UPDATE discovery_tasks SET status=CASE WHEN cancel_requested THEN 'cancelled' ELSE $2 END,result=$3,error=$4,completed_at=now(),lease_until=NULL,encrypted_secret='' WHERE id=$1 AND status='running'`, t.ID, status, b, message)
	if err == nil && t.Kind == "snmp" {
		if runErr != nil || status == "partial" {
			_, err = r.DB.ExecContext(ctx, `UPDATE discovery_sources SET consecutive_failures=least(consecutive_failures+1,6),next_poll=now()+make_interval(secs=>least(3600,60*(1<<least(consecutive_failures+1,6)))) WHERE id=$1`, t.SourceID)
		} else {
			_, err = r.DB.ExecContext(ctx, `UPDATE discovery_sources SET consecutive_failures=0 WHERE id=$1`, t.SourceID)
		}
	}
	return err
}

type DeviceQuery struct {
	Mode       string
	Window     time.Duration
	Search     string
	DeviceType string
	Category   string
	Capability string
	Limit      int
	Offset     int
}

type AddressDetail struct {
	Value   string `json:"value"`
	Family  string `json:"family"`
	Scope   string `json:"scope"`
	Primary bool   `json:"primary"`
}

type HistoricalAddress struct {
	Value    string    `json:"value"`
	LastSeen time.Time `json:"last_seen"`
}

type DeviceView struct {
	ID                  string              `json:"id"`
	PrimaryIP           string              `json:"primary_ip,omitempty"`
	Addresses           []string            `json:"addresses"`
	AddressDetails      []AddressDetail     `json:"address_details"`
	HistoricalAddresses []HistoricalAddress `json:"historical_addresses"`
	MAC                 string              `json:"mac,omitempty"`
	Name                string              `json:"name,omitempty"`
	DeviceType          string              `json:"device_type,omitempty"`
	Category            string              `json:"category"`
	IdentityKind        string              `json:"identity_kind"`
	Capabilities        []string            `json:"capabilities"`
	Protocols           []string            `json:"protocols"`
	Confidence          string              `json:"confidence"`
	FirstSeen           time.Time           `json:"first_seen"`
	LastSeen            time.Time           `json:"last_seen"`
	Current             bool                `json:"current"`
	EvidenceCount       int                 `json:"evidence_count"`
	EndpointID          string              `json:"endpoint_id,omitempty"`
	Observations        []Observation       `json:"observations"`
}

func newDeviceView(id string, observedAt time.Time) DeviceView {
	return DeviceView{
		ID: id, FirstSeen: observedAt, LastSeen: observedAt,
		Addresses: []string{}, AddressDetails: []AddressDetail{}, HistoricalAddresses: []HistoricalAddress{}, Capabilities: []string{}, Protocols: []string{}, Observations: []Observation{},
	}
}

type deviceObservationRow struct {
	DeviceKey             string
	EndpointID            string
	ProfileDeviceType     string
	ProfileTypeConfidence float64
	ProfileConflict       bool
	Observation           Observation
}

type deviceSet struct{ parent []int }

func newDeviceSet(size int) *deviceSet {
	parent := make([]int, size)
	for i := range parent {
		parent[i] = i
	}
	return &deviceSet{parent: parent}
}

func (s *deviceSet) find(value int) int {
	if s.parent[value] != value {
		s.parent[value] = s.find(s.parent[value])
	}
	return s.parent[value]
}

func (s *deviceSet) union(left, right int) {
	left, right = s.find(left), s.find(right)
	if left != right {
		s.parent[right] = left
	}
}

func discoveryScope(o Observation) string {
	return strings.Join([]string{o.Node, o.Site, o.Domain, o.VLAN, o.VRF}, "\x00")
}

func normalizedMDNSInstance(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	if marker := strings.Index(value, "._"); marker >= 0 {
		value = value[:marker]
	}
	if marker := strings.IndexByte(value, '@'); marker > 0 {
		prefix := value[:marker]
		hexOnly := len(prefix) >= 10 && len(prefix) <= 16
		for _, char := range prefix {
			if !strings.ContainsRune("0123456789abcdef", char) {
				hexOnly = false
				break
			}
		}
		if hexOnly {
			value = value[marker+1:]
		}
	}
	return strings.TrimSpace(value)
}

func deviceAliases(row deviceObservationRow) []string {
	o := row.Observation
	scope := discoveryScope(o) + "\x00"
	aliases := make([]string, 0, 7)
	if row.DeviceKey != "" {
		aliases = append(aliases, "device-key:"+row.DeviceKey)
	}
	if row.EndpointID != "" {
		aliases = append(aliases, scope+"endpoint:"+strings.ToLower(row.EndpointID))
	}
	if o.MAC != "" {
		aliases = append(aliases, scope+"mac:"+strings.ToLower(o.MAC))
	}
	if o.IP != "" {
		ipScope := scope
		if strings.HasPrefix(strings.ToLower(o.IP), "fe80:") {
			ipScope += "interface:" + o.Interface + "\x00"
		}
		aliases = append(aliases, ipScope+"ip:"+strings.ToLower(o.IP))
	}
	if o.Origin == "dns_sd" {
		if target := strings.ToLower(strings.TrimSuffix(str(o.Evidence.Payload, "service_target"), ".")); target != "" {
			aliases = append(aliases, scope+"mdns-target:"+target)
		}
		if instance := normalizedMDNSInstance(str(o.Evidence.Payload, "service_instance")); instance != "" {
			aliases = append(aliases, scope+"mdns-instance:"+instance)
		}
	}
	return aliases
}

func deviceAnchor(row deviceObservationRow) string {
	scope := discoveryScope(row.Observation) + "\x00"
	if row.EndpointID != "" {
		return scope + "endpoint:" + strings.ToLower(row.EndpointID)
	}
	if row.Observation.MAC != "" {
		return scope + "mac:" + strings.ToLower(row.Observation.MAC)
	}
	return ""
}

func betterDeviceName(candidate, current string) bool {
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	return normalizedMDNSInstance(candidate) == candidate && normalizedMDNSInstance(current) != current
}

func aggregateDeviceRows(rows []deviceObservationRow, now time.Time) []DeviceView {
	anchorsByAlias := map[string]map[string]bool{}
	for _, row := range rows {
		anchor := deviceAnchor(row)
		if anchor == "" {
			continue
		}
		for _, alias := range deviceAliases(row) {
			if anchorsByAlias[alias] == nil {
				anchorsByAlias[alias] = map[string]bool{}
			}
			anchorsByAlias[alias][anchor] = true
		}
	}
	sets := newDeviceSet(len(rows))
	firstByAlias := map[string]int{}
	for index, row := range rows {
		for _, alias := range deviceAliases(row) {
			// An alias observed with more than one reliable terminal identity is
			// ambiguous (for example an IP reused inside the 24-hour window).
			if len(anchorsByAlias[alias]) > 1 {
				continue
			}
			if first, ok := firstByAlias[alias]; ok {
				sets.union(first, index)
			} else {
				firstByAlias[alias] = index
			}
		}
	}
	type collected struct {
		view         DeviceView
		deviceKeys   map[string]bool
		addresses    map[string]bool
		caps         map[string]bool
		protocols    map[string]bool
		endpoints    map[string]bool
		profileTypes map[string]bool
	}
	groups := map[int]*collected{}
	for index, row := range rows {
		o := row.Observation
		NormalizeObservationName(&o)
		NormalizeObservationClassification(&o)
		root := sets.find(index)
		group := groups[root]
		if group == nil {
			group = &collected{view: newDeviceView(row.DeviceKey, o.ObservedAt), deviceKeys: map[string]bool{}, addresses: map[string]bool{}, caps: map[string]bool{}, protocols: map[string]bool{}, endpoints: map[string]bool{}, profileTypes: map[string]bool{}}
			groups[root] = group
		}
		group.deviceKeys[row.DeviceKey] = true
		group.view.Observations = append(group.view.Observations, o)
		group.view.EvidenceCount++
		if o.ObservedAt.Before(group.view.FirstSeen) {
			group.view.FirstSeen = o.ObservedAt
		}
		if o.ObservedAt.After(group.view.LastSeen) {
			group.view.LastSeen = o.ObservedAt
		}
		if o.Current(now) {
			group.view.Current = true
		}
		if o.IP != "" {
			group.addresses[o.IP] = true
		}
		if group.view.MAC == "" && o.MAC != "" {
			group.view.MAC = o.MAC
		}
		if betterDeviceName(o.Name, group.view.Name) {
			group.view.Name = o.Name
		}
		if group.view.DeviceType == "" && o.DeviceType != "" {
			group.view.DeviceType = o.DeviceType
		}
		for _, capability := range o.Capabilities {
			group.caps[capability] = true
		}
		group.protocols[o.Origin] = true
		if row.EndpointID != "" {
			group.endpoints[row.EndpointID] = true
		}
		if !row.ProfileConflict && row.ProfileTypeConfidence >= .8 && row.ProfileDeviceType != "" {
			group.profileTypes[row.ProfileDeviceType] = true
		}
		if confidenceRank(o.Confidence) > confidenceRank(group.view.Confidence) {
			group.view.Confidence = o.Confidence
		}
	}
	items := make([]DeviceView, 0, len(groups))
	for _, group := range groups {
		keys := make([]string, 0, len(group.deviceKeys))
		for value := range group.deviceKeys {
			keys = append(keys, value)
		}
		sort.Strings(keys)
		group.view.ID = keys[0]
		for value := range group.addresses {
			group.view.Addresses = append(group.view.Addresses, value)
		}
		sort.Slice(group.view.Addresses, func(i, j int) bool {
			leftV6, rightV6 := strings.Contains(group.view.Addresses[i], ":"), strings.Contains(group.view.Addresses[j], ":")
			if leftV6 != rightV6 {
				return !leftV6
			}
			return group.view.Addresses[i] < group.view.Addresses[j]
		})
		if len(group.view.Addresses) > 0 {
			group.view.PrimaryIP = group.view.Addresses[0]
		}
		for _, value := range group.view.Addresses {
			group.view.AddressDetails = append(group.view.AddressDetails, addressDetail(value, value == group.view.PrimaryIP))
		}
		for value := range group.caps {
			group.view.Capabilities = append(group.view.Capabilities, value)
		}
		for value := range group.protocols {
			group.view.Protocols = append(group.view.Protocols, value)
		}
		sort.Strings(group.view.Capabilities)
		sort.Strings(group.view.Protocols)
		if len(group.endpoints) == 1 {
			for value := range group.endpoints {
				group.view.EndpointID = value
			}
		}
		if group.view.DeviceType == "" && len(group.profileTypes) == 1 {
			for value := range group.profileTypes {
				group.view.DeviceType = value
			}
		}
		group.view.Category = deviceCategory(group.view.DeviceType)
		group.view.IdentityKind = deviceIdentityKind(group.view)
		items = append(items, group.view)
	}
	return items
}

func addressDetail(value string, primary bool) AddressDetail {
	detail := AddressDetail{Value: value, Family: "ipv4", Scope: "private", Primary: primary}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return detail
	}
	if address.Is6() {
		detail.Family = "ipv6"
	}
	if address.IsLinkLocalUnicast() {
		detail.Scope = "link_local"
	} else if address.IsPrivate() {
		detail.Scope = "private"
	} else {
		detail.Scope = "global"
	}
	return detail
}

func deviceCategory(deviceType string) string {
	switch strings.ToLower(strings.TrimSpace(deviceType)) {
	case "mobile", "phone", "smartphone":
		return "mobile"
	case "tablet":
		return "tablet"
	case "desktop", "computer", "laptop", "workstation":
		return "desktop"
	case "printer":
		return "printer"
	case "camera":
		return "camera"
	case "router", "switch", "access_point", "gateway":
		return "network"
	case "media_device":
		return "media"
	default:
		return "identity_only"
	}
}

func deviceIdentityKind(item DeviceView) string {
	if len(item.Addresses) > 0 {
		return "network_address"
	}
	if containsString(item.Protocols, "ieee1905_client") {
		return "link_layer_association"
	}
	return "link_layer_device"
}

func (r Repository) Devices(ctx context.Context, limit, offset int) (map[string]any, error) {
	return r.DevicesFiltered(ctx, DeviceQuery{Window: 24 * time.Hour, Limit: limit, Offset: offset})
}

func (r Repository) DevicesFiltered(ctx context.Context, query DeviceQuery) (map[string]any, error) {
	if query.Window <= 0 || query.Window > 30*24*time.Hour {
		query.Window = 24 * time.Hour
	}
	if query.Limit <= 0 || query.Limit > 200 {
		query.Limit = 50
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	origins := []string{}
	switch query.Mode {
	case "passive":
		origins = []string{"dhcp", "arp", "ndp", "dns_sd", "ssdp", "ws_discovery", "ieee1905_client"}
	case "infrastructure":
		origins = []string{"fdb", "neighbor", "lldp", "cdp"}
	case "active":
		origins = []string{"active"}
	case "", "all":
	default:
		return nil, fmt.Errorf("invalid discovery mode %q", query.Mode)
	}
	cacheKey := query.Mode + ":" + query.Window.String()
	items, err := r.DeviceCache.load(cacheKey, func() ([]DeviceView, error) {
		return r.loadDeviceViews(ctx, query.Window, origins)
	})
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(strings.TrimSpace(query.Search))
	filtered := items[:0]
	for _, item := range items {
		if query.DeviceType != "" && item.DeviceType != query.DeviceType {
			continue
		}
		if query.Capability != "" && !containsString(item.Capabilities, query.Capability) {
			continue
		}
		history := make([]string, 0, len(item.HistoricalAddresses))
		for _, address := range item.HistoricalAddresses {
			history = append(history, address.Value)
		}
		haystack := strings.ToLower(strings.Join(append(append(append([]string{item.Name, item.MAC, item.DeviceType}, item.Addresses...), history...), item.Capabilities...), " "))
		if needle != "" && !strings.Contains(haystack, needle) {
			continue
		}
		filtered = append(filtered, item)
	}
	facets := deviceFacets(filtered)
	items = filtered[:0]
	for _, item := range filtered {
		if query.Category != "" && item.Category != query.Category {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].ID < items[j].ID
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
	total := len(items)
	start, end := query.Offset, query.Offset+query.Limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	serviceDevices, linkedEndpoints := 0, 0
	for _, item := range items {
		if len(item.Capabilities) > 0 {
			serviceDevices++
		}
		if item.EndpointID != "" {
			linkedEndpoints++
		}
	}
	return map[string]any{"items": items[start:end], "total": total, "facets": facets, "service_devices": serviceDevices, "linked_endpoints": linkedEndpoints, "limit": query.Limit, "offset": query.Offset, "window": query.Window.String()}, nil
}

func (r Repository) loadDeviceViews(ctx context.Context, window time.Duration, origins []string) ([]DeviceView, error) {
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	originClause := ""
	args := []any{time.Now().Add(-window)}
	if len(origins) > 0 {
		parts := make([]string, len(origins))
		for i, origin := range origins {
			args = append(args, origin)
			parts[i] = fmt.Sprintf("$%d", len(args))
		}
		originClause = " AND origin IN (" + strings.Join(parts, ",") + ")"
	}
	// Keep observations seen inside the selected window even when their TTL has
	// expired. `current` communicates protocol validity without claiming online.
	statement := `WITH latest AS (
 SELECT DISTINCT ON (device_key,source_id,origin,coalesce(data->>'ip',''),coalesce(data->'evidence'->'payload'->>'service_type',''),coalesce(data->>'port',''))
   id,device_key,observed_at,valid_until,withdrawn,data
 FROM discovery_observations
 WHERE observed_at<=now() AND observed_at>=$1` + originClause + `
 ORDER BY device_key,source_id,origin,coalesce(data->>'ip',''),coalesce(data->'evidence'->'payload'->>'service_type',''),coalesce(data->>'port',''),observed_at DESC,id DESC)
SELECT l.device_key,l.data,coalesce(i.endpoint_id,dl.endpoint_id,''),
       coalesce(nullif(s.role,''),p.device_type,''),
       CASE WHEN coalesce(s.role,'')<>'' THEN s.confidence ELSE coalesce(p.device_type_confidence,0) END,
       CASE WHEN coalesce(s.role,'')<>'' THEN s.conflict ELSE coalesce(p.recognition_conflict,false) END
FROM latest l
LEFT JOIN discovery_identity_links i ON i.observation_id=l.id
LEFT JOIN device_address_leases dl ON dl.event_id=l.id AND dl.action='ack'
  AND dl.sensor_id=coalesce(l.data->>'node','') AND host(dl.ip)=coalesce(l.data->>'ip','')
  AND dl.campus_id=coalesce(l.data->'evidence'->'subject'->>'campus_id','')
  AND dl.endpoint_id='mac:'||lower(coalesce(l.data->>'mac',''))
LEFT JOIN endpoint_recognition_summary s ON s.endpoint_id=coalesce(i.endpoint_id,dl.endpoint_id)
LEFT JOIN endpoint_device_profiles p ON p.endpoint_id=coalesce(i.endpoint_id,dl.endpoint_id)
ORDER BY l.observed_at DESC,l.device_key`
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	deviceRows := []deviceObservationRow{}
	for rows.Next() {
		var id, endpointID, profileDeviceType string
		var profileTypeConfidence float64
		var profileConflict bool
		var b []byte
		if err = rows.Scan(&id, &b, &endpointID, &profileDeviceType, &profileTypeConfidence, &profileConflict); err != nil {
			rows.Close()
			return nil, err
		}
		var observation Observation
		if err = json.Unmarshal(b, &observation); err != nil {
			rows.Close()
			return nil, err
		}
		deviceRows = append(deviceRows, deviceObservationRow{DeviceKey: id, EndpointID: endpointID, ProfileDeviceType: profileDeviceType, ProfileTypeConfidence: profileTypeConfidence, ProfileConflict: profileConflict, Observation: observation})
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	items := aggregateDeviceRows(deviceRows, time.Now())
	if err = attachHistoricalAddresses(ctx, tx, items); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

func attachHistoricalAddresses(ctx context.Context, tx *sql.Tx, items []DeviceView) error {
	endpointItems := map[string][]int{}
	for index := range items {
		if items[index].EndpointID != "" && len(items[index].Addresses) == 0 {
			endpointItems[items[index].EndpointID] = append(endpointItems[items[index].EndpointID], index)
		}
	}
	if len(endpointItems) == 0 {
		return nil
	}
	ids := make([]string, 0, len(endpointItems))
	for endpointID := range endpointItems {
		ids = append(ids, endpointID)
	}
	sort.Strings(ids)
	args := make([]any, len(ids))
	placeholders := make([]string, len(ids))
	for index, endpointID := range ids {
		args[index] = endpointID
		placeholders[index] = fmt.Sprintf("$%d", index+1)
	}
	statement := `WITH recent AS (
 SELECT endpoint_id,host(ip) value,max(last_seen) last_seen
 FROM identity_ip_mac_history
 WHERE endpoint_id IN (` + strings.Join(placeholders, ",") + `) AND last_seen>=now()-interval '30 days'
 GROUP BY endpoint_id,host(ip)
), ranked AS (
 SELECT endpoint_id,value,last_seen,row_number() OVER(PARTITION BY endpoint_id ORDER BY last_seen DESC,value) rank
 FROM recent
)
SELECT endpoint_id,value,last_seen FROM ranked WHERE rank<=3 ORDER BY endpoint_id,last_seen DESC,value`
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var endpointID, value string
		var lastSeen time.Time
		if err = rows.Scan(&endpointID, &value, &lastSeen); err != nil {
			return err
		}
		for _, index := range endpointItems[endpointID] {
			items[index].HistoricalAddresses = append(items[index].HistoricalAddresses, HistoricalAddress{Value: value, LastSeen: lastSeen})
		}
	}
	return rows.Err()
}

type DeviceFacet struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

func deviceFacets(items []DeviceView) []DeviceFacet {
	order := []string{"all", "mobile", "tablet", "desktop", "printer", "camera", "network", "media", "identity_only"}
	counts := map[string]int{"all": len(items)}
	for _, item := range items {
		counts[item.Category]++
	}
	result := make([]DeviceFacet, 0, len(order))
	for _, category := range order {
		result = append(result, DeviceFacet{Category: category, Count: counts[category]})
	}
	return result
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func confidenceRank(value string) int {
	switch value {
	case "confirmed":
		return 3
	case "strong":
		return 2
	case "clue":
		return 1
	}
	return 0
}
