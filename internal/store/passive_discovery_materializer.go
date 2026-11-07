package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

type passiveDiscoveryCursor struct {
	Timestamp time.Time
	EventID   string
	Owner     string
}

type passiveDiscoveryRow struct {
	Timestamp       string  `json:"event_timestamp"`
	EventID         string  `json:"event_id"`
	Source          string  `json:"source"`
	SourceEventType string  `json:"source_event_type"`
	Type            string  `json:"type"`
	SensorID        string  `json:"sensor_id"`
	CampusID        string  `json:"campus_id"`
	SubjectIP       string  `json:"subject_ip"`
	SubjectMAC      string  `json:"subject_mac"`
	ObserverJSON    string  `json:"observer_json"`
	PayloadJSON     string  `json:"payload_json"`
	FlowJSON        string  `json:"flow_json"`
	Confidence      float64 `json:"confidence"`
}

type passiveDiscoveryBatchStats struct {
	Processed int
	Emitted   int
	Skipped   int
	Protocols map[string]int
	Reasons   map[string]int
}

type passiveDiscoveryDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// A passive event can fan out into several PostgreSQL lookups and idempotent
// writes (notably mDNS). The event and encoded-byte limits keep each claim
// inside the 90-second lease and 45-second work budget. The larger event
// window merges repeated ARP and mDNS facts before the PostgreSQL writes.
//
// Measured on the 204 sensor, one published observation costs a few
// milliseconds once its index pages are cached, so a 500-event floor keeps the
// per-batch read overhead amortised instead of collapsing to tiny claims the
// way the old 125-event floor did.
const (
	passiveDiscoveryBatchSize  = 1500
	passiveDiscoveryBatchBytes = 6 << 20
	passiveDiscoveryMinBatch   = 500
	passiveDiscoveryMaxBatch   = 1500
)

type passiveDiscoveryBatchTuner struct {
	limit     int
	successes int
}

// A slow batch retries from the unchanged cursor at a smaller size. The floor
// stays high enough that one timeout cannot pin the cursor in a tiny-claim
// loop, and three full successes restore the cap so a transient hotspot does
// not permanently halve throughput.
func (t *passiveDiscoveryBatchTuner) observe(full bool, err error) {
	if err != nil {
		switch discovery.WorkErrorCode(err) {
		case "deadline_exceeded", "database_40P01":
			t.limit = max(passiveDiscoveryMinBatch, t.limit/2)
			t.successes = 0
		}
		return
	}
	if !full {
		t.successes = 0
		return
	}
	t.successes++
	if t.successes >= 3 {
		t.limit = min(passiveDiscoveryMaxBatch, t.limit*2)
		t.successes = 0
	}
}

// passiveSlowBatchLogUnix rate-limits the slow-batch diagnostics to one line
// per ten seconds so a busy catch-up cannot flood the journal.
var passiveSlowBatchLogUnix atomic.Int64

// passiveBatchMu serialises this process's two PostgreSQL writers (the main
// discovery materializer and the live mDNS PTR worker). They touch the same
// latest-observation and endpoint rows; letting them interleave produced
// multi-second lock waits inside the same process.
var passiveBatchMu sync.Mutex

func logSlowPassiveBatch(stats passiveDiscoveryBatchStats, sections map[string]time.Duration, total time.Duration) {
	if total < 3*time.Second {
		return
	}
	now := time.Now().Unix()
	last := passiveSlowBatchLogUnix.Load()
	if now-last < 10 || !passiveSlowBatchLogUnix.CompareAndSwap(last, now) {
		return
	}
	fmt.Fprintf(os.Stderr, "passive discovery slow batch: processed=%d emitted=%d skipped=%d arp_candidates=%s arp_batch=%s mdns=%s observe=%s link_batch=%s commit=%s total=%s\n",
		stats.Processed, stats.Emitted, stats.Skipped,
		sections["arp_candidates"].Round(time.Millisecond), sections["arp_batch"].Round(time.Millisecond),
		sections["mdns"].Round(time.Millisecond), sections["observe"].Round(time.Millisecond),
		sections["link_batch"].Round(time.Millisecond),
		sections["commit"].Round(time.Millisecond), total.Round(time.Millisecond))
}

type passiveDiscoveryScope struct{ prefixes []netip.Prefix }

func parsePassiveDiscoveryScope(raw string) (passiveDiscoveryScope, error) {
	var result passiveDiscoveryScope
	for _, value := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 {
			return result, fmt.Errorf("invalid passive discovery CIDR %q", value)
		}
		result.prefixes = append(result.prefixes, prefix.Masked())
	}
	if len(result.prefixes) == 0 {
		return result, fmt.Errorf("PROXY_SENTINEL_DISCOVERY_CIDRS is required")
	}
	return result, nil
}

func (s passiveDiscoveryScope) allows(value string) bool {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return false
	}
	address = address.Unmap()
	if address.Is6() && address.IsLinkLocalUnicast() {
		return true
	}
	for _, prefix := range s.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *DBStore) claimPassiveDiscovery(ctx context.Context, sensorID, owner string) (passiveDiscoveryCursor, bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return passiveDiscoveryCursor{}, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO passive_discovery_state(sensor_id) VALUES($1) ON CONFLICT DO NOTHING`, sensorID); err != nil {
		return passiveDiscoveryCursor{}, false, err
	}
	var cursor passiveDiscoveryCursor
	var leased bool
	if err = tx.QueryRowContext(ctx, `SELECT cursor_timestamp,cursor_event_id,lease_until>now() FROM passive_discovery_state WHERE sensor_id=$1 FOR UPDATE`, sensorID).Scan(&cursor.Timestamp, &cursor.EventID, &leased); err != nil {
		return passiveDiscoveryCursor{}, false, err
	}
	if leased {
		return passiveDiscoveryCursor{}, false, tx.Commit()
	}
	cursor.Owner = owner
	if _, err = tx.ExecContext(ctx, `UPDATE passive_discovery_state SET lease_owner=$2,lease_until=now()+interval '90 seconds',updated_at=now() WHERE sensor_id=$1`, sensorID, owner); err != nil {
		return passiveDiscoveryCursor{}, false, err
	}
	return cursor, true, tx.Commit()
}

func (s *DBStore) passiveDiscoveryEvents(ctx context.Context, sensorID string, cursor passiveDiscoveryCursor, limit int) ([]normalized.Event, passiveDiscoveryCursor, bool, error) {
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	cutoff, err := passiveDiscoveryReadCutoff(time.Now())
	if err != nil {
		return nil, cursor, false, err
	}
	stamp := "parseDateTime64BestEffort(" + chQuote(cursor.Timestamp.UTC().Format(time.RFC3339Nano)) + ",6)"
	upper := "parseDateTime64BestEffort(" + chQuote(cutoff.UTC().Format(time.RFC3339Nano)) + ",6)"
	where := "sensor_id=" + chQuote(sensorID) + " AND timestamp>=" + stamp + " AND timestamp<" + upper + " AND (" + chAfterBound([]chBoundKey{{Expr: "timestamp", Value: stamp}, {Expr: "event_id", Value: chQuote(cursor.EventID)}}) + ")"
	if os.Getenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_DHCP_ONLY") == "true" {
		where += " AND source_event_type='dhcp'"
	} else {
		where += " AND source_event_type IN ('dhcp','arp','ndp','mdns','ssdp','ws_discovery','lldp','cdp','ieee1905_client_association','ieee1905_topology')"
	}
	query := fmt.Sprintf(`SELECT formatDateTime(timestamp,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') event_timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence FROM passive_discovery_events_v2 PREWHERE %s ORDER BY timestamp,event_id LIMIT %d SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`, where, limit)
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return nil, cursor, false, err
	}
	readBytes := len(raw)
	raw, err = boundedPassiveDiscoveryRows(raw, passiveDiscoveryBatchBytes)
	if err != nil {
		return nil, cursor, false, err
	}
	truncated := len(raw) < readBytes
	rows := []passiveDiscoveryRow{}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return nil, cursor, false, err
	}
	events := make([]normalized.Event, 0, len(rows))
	next := cursor
	for _, row := range rows {
		stamp, parseErr := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.Timestamp))
		if parseErr != nil {
			return nil, cursor, false, parseErr
		}
		event := normalized.Event{SchemaVersion: "v1", EventID: row.EventID, Source: row.Source, SourceEventType: row.SourceEventType, Type: row.Type, Timestamp: stamp.UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": row.SensorID}, Subject: map[string]any{"ip": row.SubjectIP, "mac": row.SubjectMAC, "campus_id": row.CampusID}, Payload: map[string]any{}, Flow: map[string]any{}, Confidence: row.Confidence}
		_ = json.Unmarshal([]byte(row.ObserverJSON), &event.Observer)
		_ = json.Unmarshal([]byte(row.PayloadJSON), &event.Payload)
		_ = json.Unmarshal([]byte(row.FlowJSON), &event.Flow)
		event.Observer["sensor_id"] = row.SensorID
		events = append(events, event)
		next.Timestamp, next.EventID = stamp.UTC(), row.EventID
	}
	return events, next, truncated, nil
}

// ClickHouse returns rows sorted by timestamp and event ID. Keep only a
// complete prefix when the encoded result exceeds the transaction byte budget;
// the persisted cursor stops at its last row, so the remainder is read next.
func boundedPassiveDiscoveryRows(raw []byte, maxBytes int) ([]byte, error) {
	if len(raw) <= maxBytes {
		return raw, nil
	}
	lastComplete := bytes.LastIndexByte(raw[:maxBytes], '\n')
	if lastComplete < 0 {
		return nil, fmt.Errorf("passive discovery event exceeds %d-byte batch budget", maxBytes)
	}
	return raw[:lastComplete+1], nil
}

func passiveDiscoveryReadCutoff(now time.Time) (time.Time, error) {
	holdback := 2 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_HOLDBACK")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < 30*time.Second || parsed > 30*time.Minute {
			return time.Time{}, fmt.Errorf("invalid passive discovery holdback %q: expected 30s..30m", raw)
		}
		holdback = parsed
	}
	return now.Add(-holdback), nil
}

func passiveString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	value, ok := m[key]
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

// passiveSelfReport extracts the manufacturer and product model a device
// advertises about itself. The nested UPnP description only counts when the
// top-level payload does not already carry the field.
func passiveSelfReport(payload map[string]any) (string, string) {
	manufacturer := passiveString(payload, "manufacturer")
	model := passiveString(payload, "product_model")
	if description, ok := payload["description"].(map[string]any); ok {
		if manufacturer == "" {
			manufacturer = passiveString(description, "manufacturer")
		}
		if model == "" {
			model = strings.TrimSpace(passiveString(description, "model_name") + " " + passiveString(description, "model_number"))
		}
	}
	return discovery.CleanReportedText(manufacturer), discovery.CleanReportedText(model)
}

func passiveInterface(event normalized.Event) string {
	if value := passiveString(event.Observer, "interface"); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv("PROXY_SENTINEL_MIRROR_INTERFACE"))
}

func passiveTTL(payload map[string]any, fallback int) int {
	for _, key := range []string{"record_ttl", "ttl", "lease_time"} {
		value := passiveString(payload, key)
		if value == "" || value == "<nil>" {
			continue
		}
		if number, err := strconv.ParseFloat(value, 64); err == nil && number >= 0 {
			if number > 7*24*3600 {
				number = 7 * 24 * 3600
			}
			return int(number)
		}
	}
	return fallback
}

func validPassiveMAC(value string) string {
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return ""
	}
	return strings.ToLower(mac.String())
}

func passiveRandomMAC(value string) bool {
	mac, err := net.ParseMAC(value)
	return err == nil && len(mac) == 6 && mac[0]&2 != 0
}

func passiveObservation(event normalized.Event, scope passiveDiscoveryScope) (discovery.Observation, string) {
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil || event.EventID == "" {
		return discovery.Observation{}, "invalid_event"
	}
	kind := strings.ToLower(strings.TrimSpace(event.SourceEventType))
	ip := strings.TrimSpace(passiveString(event.Subject, "ip"))
	mac := validPassiveMAC(passiveString(event.Subject, "mac"))
	interfaceName := passiveInterface(event)
	campus := passiveString(event.Subject, "campus_id")
	domain := passiveString(event.Payload, "access_domain")
	if domain == "" {
		domain = interfaceName
	}
	o := discovery.Observation{ID: event.EventID, EventID: event.EventID, SourceID: "passive:" + passiveString(event.Observer, "sensor_id") + ":" + interfaceName, Node: passiveString(event.Observer, "sensor_id"), Site: campus, Domain: domain, VLAN: passiveString(event.Payload, "vlan"), IP: ip, MAC: mac, Interface: interfaceName, ObservedAt: at, Evidence: event, RuleVersion: discovery.RuleVersion, Confidence: "strong"}
	if o.Site == "" {
		o.Site = o.Node
	}
	switch kind {
	case "dhcp":
		if !strings.Contains(strings.ToUpper(passiveString(event.Payload, "msg_types")), "ACK") || mac == "" || !scope.allows(ip) {
			return discovery.Observation{}, "dhcp_not_ack_or_out_of_scope"
		}
		o.Origin, o.Name, o.Explanation = "dhcp", passiveString(event.Payload, "client_fqdn"), "DHCP 确认的地址与 MAC 绑定"
		nameField := "client_fqdn"
		if o.Name == "" {
			o.Name = passiveString(event.Payload, "hostname")
			nameField = "hostname"
		}
		o.OriginalName = passiveString(event.Payload, nameField+"_original")
		o.NameEncoding = passiveString(event.Payload, nameField+"_encoding")
		o.Confidence = "confirmed"
		o.ValidUntil = at.Add(time.Duration(passiveTTL(event.Payload, 24*3600)) * time.Second)
	case "arp":
		if mac == "" || !scope.allows(ip) {
			return discovery.Observation{}, "arp_out_of_scope"
		}
		o.Origin, o.Explanation, o.ValidUntil = "arp", "ARP 链路层地址声明", at.Add(10*time.Minute)
		o.Confidence = "confirmed"
	case "ndp":
		if mac == "" || !scope.allows(ip) {
			return discovery.Observation{}, "ndp_out_of_scope"
		}
		o.Origin, o.Explanation, o.ValidUntil = "ndp", "IPv6 邻居发现地址声明", at.Add(10*time.Minute)
		o.Confidence = "confirmed"
	case "ieee1905_client_association":
		client := validPassiveMAC(passiveString(event.Payload, "client_mac"))
		if client == "" {
			return discovery.Observation{}, "invalid_ieee1905_client"
		}
		o.MAC, o.IP, o.Origin, o.Explanation = client, "", "ieee1905_client", "IEEE 1905 客户关联公告"
		o.ValidUntil = at.Add(24 * time.Hour)
		o.Confidence = "confirmed"
		if passiveString(event.Payload, "association_state") != "joined" {
			o.Withdrawn, o.ValidUntil = true, at
		}
	case "ieee1905_topology":
		// Only the mesh node itself originates 1905 topology messages; the
		// subject MAC is its AL MAC, not a client behind it.
		if mac == "" {
			return discovery.Observation{}, "ieee1905_no_mac"
		}
		o.Origin, o.Explanation, o.ValidUntil = "ieee1905", "IEEE 1905 网格拓扑声明", at.Add(10*time.Minute)
		o.DeviceType, o.Capabilities = "access_point", []string{"routing"}
		o.Confidence = "strong"
	case "ssdp":
		if !scope.allows(ip) {
			return discovery.Observation{}, "ssdp_out_of_scope"
		}
		service := strings.ToLower(passiveString(event.Payload, "st") + " " + passiveString(event.Payload, "nt"))
		o.Origin, o.Explanation, o.ValidUntil = "ssdp", "SSDP 设备响应或公告", at.Add(30*time.Minute)
		// A description-enriched advertisement carries the device's own
		// manufacturer and model. Keep them as self-report evidence; they do not
		// confirm a whole-device type on their own.
		if manufacturer, model := passiveSelfReport(event.Payload); manufacturer != "" || model != "" {
			o.Manufacturer, o.ModelName = manufacturer, model
			o.Explanation = "SSDP 设备描述自报型号，不确认整机类型"
		}
		if strings.Contains(service, "internetgatewaydevice") {
			o.DeviceType, o.Capabilities = "gateway", []string{"routing"}
		} else if strings.Contains(service, "mediarenderer") {
			o.DeviceType, o.Capabilities = "media_device", []string{"media_rendering"}
		}
	case "ws_discovery":
		if !scope.allows(ip) {
			return discovery.Observation{}, "ws_discovery_out_of_scope"
		}
		o.Origin, o.Explanation, o.ValidUntil = "ws_discovery", "WS-Discovery 设备自报响应", at.Add(30*time.Minute)
		types := strings.ToLower(passiveString(event.Payload, "types"))
		if strings.Contains(types, "networkvideotransmitter") || strings.Contains(types, "onvif") {
			o.DeviceType, o.Capabilities = "camera", []string{"network_video"}
		}
		if passiveString(event.Payload, "withdrawn") == "true" {
			o.Withdrawn, o.ValidUntil = true, at
		}
	case "lldp", "cdp":
		if ip != "" && !scope.allows(ip) {
			o.IP = ""
		}
		if o.IP == "" && mac == "" {
			return discovery.Observation{}, "infrastructure_without_identity"
		}
		o.Origin, o.Name, o.Explanation, o.ValidUntil = kind, passiveString(event.Payload, "system_name"), strings.ToUpper(kind)+" 网络基础设施公告", at.Add(10*time.Minute)
		o.OriginalName = passiveString(event.Payload, "system_name_original")
		o.NameEncoding = passiveString(event.Payload, "system_name_encoding")
		caps := strings.ToLower(passiveString(event.Payload, "system_capabilities") + "," + passiveString(event.Payload, "capabilities"))
		switch {
		case strings.Contains(caps, "router"):
			o.DeviceType = "router"
		case strings.Contains(caps, "wlan"):
			o.DeviceType = "access_point"
		case strings.Contains(caps, "bridge") || strings.Contains(caps, "switch"):
			o.DeviceType = "switch"
		}
	default:
		return discovery.Observation{}, "unsupported_protocol"
	}
	discovery.NormalizeObservationClassification(&o)
	discovery.NormalizeObservationName(&o)
	if id := passiveRepeatableFactID(o); id != "" {
		o.ID = id
	}
	return o, ""
}

// passiveRepeatableFactID collapses repeated address claims into one row per
// fact. A frame-per-second ARP or NDP stream would otherwise insert a row, an
// identity link and a recognition job for every frame. The raw frames stay in
// ClickHouse; the projection keeps one row per fact and refreshes its last-seen
// and latest-observation view on every repeat. The key deliberately excludes a
// time bucket so an active fact does not rewrite the whole table at each hour
// boundary; a change of address, interface or DHCP name starts a new row.
func passiveRepeatableFactID(o discovery.Observation) string {
	switch o.Origin {
	case "arp", "ndp", "dhcp", "ieee1905":
	default:
		return ""
	}
	key := strings.Join([]string{o.Origin, o.SourceID, o.MAC, o.IP, o.Name}, "\x00")
	sum := sha256.Sum256([]byte(key))
	return "fact-" + hex.EncodeToString(sum[:16])
}

func passiveServiceType(name string) string {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, marker := range []string{"_ipps._tcp", "_ipp._tcp", "_printer._tcp", "_uscan._tcp", "_scanner._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp"} {
		if strings.Contains(lower, marker) {
			return marker
		}
	}
	return ""
}

func passiveCapabilities(service string) []string {
	switch service {
	case "_ipp._tcp", "_ipps._tcp", "_printer._tcp":
		return []string{"printing"}
	case "_uscan._tcp", "_scanner._tcp":
		return []string{"scanning"}
	case "_airplay._tcp", "_raop._tcp", "_googlecast._tcp":
		return []string{"casting"}
	}
	return nil
}

func passivePrinterType(capabilities []string, values ...string) string {
	if len(capabilities) == 0 || capabilities[0] != "printing" {
		return ""
	}
	combined := strings.ToLower(strings.Join(values, " "))
	if strings.Contains(combined, "laserjet") || strings.Contains(combined, "printer") || strings.Contains(combined, "ty=") || strings.Contains(combined, "product=") {
		return "printer"
	}
	return ""
}

func passiveHostToken(name string) string {
	label := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".local")
	end := len(label)
	start := end
	for start > 0 && strings.ContainsRune("0123456789abcdef", rune(label[start-1])) {
		start--
	}
	token := label[start:end]
	if len(token) < 6 || len(token) > 16 {
		return ""
	}
	return token
}

func passivePTRObservation(event normalized.Event, sensor, iface, recordName, instance string, at, validUntil time.Time, scope passiveDiscoveryScope) (discovery.Observation, bool) {
	service := passiveServiceType(recordName)
	capabilities := passiveCapabilities(service)
	address := passiveString(event.Subject, "ip")
	if len(capabilities) == 0 || !scope.allows(address) {
		return discovery.Observation{}, false
	}
	name := strings.TrimSpace(strings.Split(instance, "._")[0])
	hash := sha256.Sum256([]byte(strings.Join([]string{sensor, iface, "ptr", instance, address, event.EventID}, "\x00")))
	payload := map[string]any{"origin": "dns_sd", "is_response": true, "service_type": service, "service_instance": instance, "service_source": "ptr_responder", "ttl": int(validUntil.Sub(at).Seconds())}
	evidence := event
	evidence.EventID = "dns-sd-" + hex.EncodeToString(hash[:16])
	evidence.Type, evidence.SourceEventType, evidence.Payload = "discovery", "dns_sd", payload
	evidence.Subject = map[string]any{"ip": address, "campus_id": passiveString(event.Subject, "campus_id")}
	directMAC := ""
	if event.Source == "zeek" && event.Payload["l2_source_mac_direct"] == true {
		if destination, err := netip.ParseAddr(passiveString(event.Flow, "dst_ip")); err == nil && destination.IsMulticast() {
			directMAC = validPassiveMAC(passiveString(event.Payload, "responder_l2_mac"))
		}
	}
	if directMAC != "" {
		evidence.Subject["mac"] = directMAC
		evidence.Payload["l2_source_mac_direct"] = true
		evidence.Payload["responder_l2_mac"] = directMAC
	}
	observation := discovery.Observation{ID: evidence.EventID, EventID: evidence.EventID, SourceID: "passive:" + sensor + ":" + iface, Node: sensor, Site: passiveString(event.Subject, "campus_id"), Domain: passiveString(event.Payload, "access_domain"), IP: address, MAC: directMAC, Name: name, Origin: "dns_sd", DeviceType: passivePrinterType(capabilities, instance), Capabilities: capabilities, Confidence: "strong", Explanation: "DNS-SD 服务响应由报文源地址被动关联", RuleVersion: discovery.RuleVersion, ObservedAt: at, ValidUntil: validUntil, Interface: iface, Evidence: evidence}
	if observation.Site == "" {
		observation.Site = sensor
	}
	if observation.Domain == "" {
		observation.Domain = iface
	}
	return observation, true
}

func (s *DBStore) passivePTRAddressObservations(ctx context.Context, db passiveDiscoveryDB, event normalized.Event, sensor, iface, host, address string, at, addressUntil time.Time, scope passiveDiscoveryScope) ([]discovery.Observation, error) {
	token := passiveHostToken(host)
	if token == "" || !scope.allows(address) {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT record_name,record_value,least(valid_until,$4) FROM passive_discovery_mdns_records WHERE sensor_id=$1 AND interface_name=$2 AND record_type='PTR' AND valid_until>$3 AND lower(record_value) LIKE $5`, sensor, iface, at, addressUntil, "%["+token+"]%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []discovery.Observation{}
	for rows.Next() {
		var serviceName, instance string
		var validUntil time.Time
		if err = rows.Scan(&serviceName, &instance, &validUntil); err != nil {
			return nil, err
		}
		addressEvent := event
		addressEvent.Subject = map[string]any{"ip": address, "campus_id": passiveString(event.Subject, "campus_id")}
		observation, ok := passivePTRObservation(addressEvent, sensor, iface, serviceName, instance, at, validUntil, scope)
		if !ok {
			continue
		}
		observation.Explanation = "DNS-SD 服务实例标识与地址主机名自动关联"
		observation.Evidence.Payload["service_source"] = "ptr_host_token"
		observation.Evidence.Payload["service_target"] = host
		result = append(result, observation)
	}
	return result, rows.Err()
}

func (s *DBStore) materializeMDNS(ctx context.Context, db passiveDiscoveryDB, event normalized.Event, scope passiveDiscoveryScope) ([]discovery.Observation, string, error) {
	if passiveString(event.Payload, "is_response") != "true" {
		return nil, "mdns_query", nil
	}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return nil, "invalid_event", nil
	}
	sensor, iface := passiveString(event.Observer, "sensor_id"), passiveInterface(event)
	recordType := strings.ToUpper(passiveString(event.Payload, "record_type"))
	recordName := strings.ToLower(strings.TrimSuffix(passiveString(event.Payload, "record_name"), "."))
	value := passiveString(event.Payload, "record_address")
	if recordType == "SRV" || recordType == "PTR" {
		value = strings.ToLower(strings.TrimSuffix(passiveString(event.Payload, "service_target"), "."))
	}
	if recordType == "TXT" {
		value = passiveString(event.Payload, "record_text")
	}
	if sensor == "" || recordName == "" || value == "" || !map[string]bool{"A": true, "AAAA": true, "SRV": true, "PTR": true, "TXT": true}[recordType] {
		return nil, "invalid_mdns_record", nil
	}
	if (recordType == "A" || recordType == "AAAA") && !scope.allows(value) {
		return nil, "mdns_address_out_of_scope", nil
	}
	ttl := passiveTTL(event.Payload, 120)
	validUntil := at.Add(time.Duration(ttl) * time.Second)
	// PTR, SRV and TXT records outside the supported service families cannot
	// produce a discovery observation or contribute to a supported SRV join.
	// Keep A/AAAA host addresses for those joins and process zero-TTL records
	// so older projections can still be withdrawn after a rule change.
	if ttl > 0 && recordType != "A" && recordType != "AAAA" && passiveServiceType(recordName) == "" {
		return nil, "mdns_unusable_service", nil
	}
	raw, _ := json.Marshal(event.Payload)
	if ttl == 0 {
		_, err = db.ExecContext(ctx, `DELETE FROM passive_discovery_mdns_records WHERE sensor_id=$1 AND interface_name=$2 AND record_name=$3 AND record_type=$4 AND record_value=$5`, sensor, iface, recordName, recordType, value)
		if err == nil {
			switch recordType {
			case "A", "AAAA":
				_, err = db.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=$1,withdrawn=true WHERE origin='dns_sd' AND source_id=$2 AND data->>'ip'=$3 AND observed_at<=$1 AND NOT withdrawn AND valid_until>$1`, at, "passive:"+sensor+":"+iface, value)
			case "SRV", "TXT":
				_, err = db.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=$1,withdrawn=true WHERE origin='dns_sd' AND source_id=$2 AND data->'evidence'->'payload'->>'service_instance'=$3 AND observed_at<=$1 AND NOT withdrawn AND valid_until>$1`, at, "passive:"+sensor+":"+iface, recordName)
			case "PTR":
				_, err = db.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=$1,withdrawn=true WHERE origin='dns_sd' AND source_id=$2 AND data->'evidence'->'payload'->>'service_instance'=$3 AND observed_at<=$1 AND NOT withdrawn AND valid_until>$1`, at, "passive:"+sensor+":"+iface, value)
			}
		}
	} else {
		_, err = db.ExecContext(ctx, `INSERT INTO passive_discovery_mdns_records(sensor_id,interface_name,record_name,record_type,record_value,observed_at,valid_until,event_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(sensor_id,interface_name,record_name,record_type,record_value) DO UPDATE SET observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,event_id=EXCLUDED.event_id,payload=EXCLUDED.payload WHERE EXCLUDED.observed_at>=passive_discovery_mdns_records.observed_at`, sensor, iface, recordName, recordType, value, at, validUntil, event.EventID, raw)
	}
	if err != nil || ttl == 0 {
		return nil, "", err
	}

	result := []discovery.Observation{}
	if recordType == "PTR" {
		if observation, ok := passivePTRObservation(event, sensor, iface, recordName, value, at, validUntil, scope); ok {
			result = append(result, observation)
		}
	}
	if recordType == "A" || recordType == "AAAA" {
		linked, linkErr := s.passivePTRAddressObservations(ctx, db, event, sensor, iface, recordName, value, at, validUntil, scope)
		if linkErr != nil {
			return nil, "", linkErr
		}
		result = append(result, linked...)
	}
	rows, err := db.QueryContext(ctx, `SELECT srv.record_name,srv.record_value,addr.record_value,least(srv.valid_until,addr.valid_until),coalesce(txt.record_value,''),greatest(srv.observed_at,addr.observed_at),srv.event_id
FROM passive_discovery_mdns_records srv
JOIN passive_discovery_mdns_records addr ON addr.sensor_id=srv.sensor_id AND addr.interface_name=srv.interface_name AND addr.record_name=srv.record_value AND addr.record_type IN ('A','AAAA') AND addr.valid_until>$3
LEFT JOIN passive_discovery_mdns_records txt ON txt.sensor_id=srv.sensor_id AND txt.interface_name=srv.interface_name AND txt.record_name=srv.record_name AND txt.record_type='TXT' AND txt.valid_until>$3
WHERE srv.sensor_id=$1 AND srv.interface_name=$2 AND srv.record_type='SRV' AND srv.valid_until>$3 AND (srv.record_name=$4 OR srv.record_value=$4 OR addr.record_name=$4)`, sensor, iface, at, recordName)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var instance, target, address, textValue, srvEventID string
		var until, observed time.Time
		if err = rows.Scan(&instance, &target, &address, &until, &textValue, &observed, &srvEventID); err != nil {
			return nil, "", err
		}
		service := passiveServiceType(instance)
		capabilities := passiveCapabilities(service)
		if len(capabilities) == 0 {
			continue
		}
		hash := sha256.Sum256([]byte(strings.Join([]string{sensor, iface, instance, target, address, srvEventID}, "\x00")))
		name := strings.TrimSpace(strings.Split(instance, "._")[0])
		deviceType := passivePrinterType(capabilities, instance, textValue)
		payload := map[string]any{"origin": "dns_sd", "is_response": true, "service_type": service, "service_instance": instance, "service_target": target, "txt": textValue, "ttl": int(until.Sub(observed).Seconds())}
		evidence := event
		evidence.EventID = "dns-sd-" + hex.EncodeToString(hash[:16])
		evidence.Type, evidence.SourceEventType, evidence.Payload = "discovery", "dns_sd", payload
		evidence.Subject = map[string]any{"ip": address, "campus_id": passiveString(event.Subject, "campus_id")}
		o := discovery.Observation{ID: evidence.EventID, EventID: evidence.EventID, SourceID: "passive:" + sensor + ":" + iface, Node: sensor, Site: passiveString(event.Subject, "campus_id"), Domain: passiveString(event.Payload, "access_domain"), IP: address, Name: name, Origin: "dns_sd", DeviceType: deviceType, Capabilities: capabilities, ModelName: discovery.DNSSDModelFromTXT(textValue), Confidence: "strong", Explanation: "DNS-SD 服务响应与地址记录自动关联", RuleVersion: discovery.RuleVersion, ObservedAt: observed, ValidUntil: until, Interface: iface, Evidence: evidence}
		if o.Site == "" {
			o.Site = sensor
		}
		if o.Domain == "" {
			o.Domain = iface
		}
		result = append(result, o)
	}
	return result, "", rows.Err()
}

// passiveLinkRow is one pending identity link. Links are written once per batch
// in endpoint order so concurrent writers cannot take endpoint row locks in
// opposite orders (the dominant deadlock cycle with name evidence and the
// recognition summary).
type passiveLinkRow struct {
	ObservationID string          `json:"observation_id"`
	EndpointID    string          `json:"endpoint_id"`
	ValidUntil    time.Time       `json:"valid_until"`
	Basis         json.RawMessage `json:"basis"`
}

func (s *DBStore) insertPassiveObservation(ctx context.Context, db passiveDiscoveryDB, o discovery.Observation) (*passiveLinkRow, error) {
	if o.ID == "" || o.ObservedAt.IsZero() {
		return nil, nil
	}
	if o.ValidUntil.IsZero() {
		o.ValidUntil = o.ObservedAt.Add(24 * time.Hour)
	}
	// Service advertisements usually carry an IP but no MAC. Reuse only an
	// event-time DHCP/ARP/NDP binding; never manufacture a terminal identity.
	if o.MAC == "" && o.IP != "" {
		var mac string
		err := db.QueryRowContext(ctx, `SELECT lower(data->>'mac')
FROM discovery_observations
WHERE data->>'node'=$1 AND data->>'ip'=$2 AND coalesce(data->>'mac','')<>''
  AND origin IN ('dhcp','arp','ndp') AND observed_at<=$3 AND valid_until>$3
ORDER BY observed_at DESC,id DESC LIMIT 1`, o.Node, o.IP, o.ObservedAt).Scan(&mac)
		if err == nil {
			o.MAC = validPassiveMAC(mac)
		} else if err != sql.ErrNoRows {
			return nil, err
		}
	}
	raw, _ := json.Marshal(o)
	if _, err := db.ExecContext(ctx, `INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET device_key=EXCLUDED.device_key,source_id=EXCLUDED.source_id,origin=EXCLUDED.origin,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,data=EXCLUDED.data WHERE EXCLUDED.observed_at>=discovery_observations.observed_at`, o.ID, o.Key(), o.SourceID, o.Origin, o.ObservedAt, o.ValidUntil, o.Withdrawn, raw); err != nil {
		return nil, err
	}
	return s.passiveObservationLink(ctx, db, o)
}

func (s *DBStore) passiveObservationLink(ctx context.Context, db passiveDiscoveryDB, o discovery.Observation) (*passiveLinkRow, error) {
	mac := validPassiveMAC(o.MAC)
	if mac == "" {
		return nil, nil
	}
	if passiveRandomMAC(mac) && o.IP == "" {
		return nil, nil
	}
	endpointID := "mac:" + mac
	// ARP's sender hardware address and sender protocol address come from the
	// same frame. This observation can link to an existing endpoint by that
	// exact MAC without a DHCP lease. A verified multicast PTR responder has
	// the same direct frame-level ownership; other IP/MAC claims need a lease.
	if o.IP != "" && o.Origin != "arp" && !passiveDirectResponderIdentity(o) {
		var leaseEndpoint string
		err := db.QueryRowContext(ctx, `SELECT endpoint_id FROM device_address_leases WHERE sensor_id=$1 AND campus_id=$2 AND ip=$3::inet AND action='ack' AND observed_at<=$4 AND valid_until>$4 ORDER BY observed_at DESC,event_id DESC LIMIT 1`, o.Node, passiveString(o.Evidence.Subject, "campus_id"), o.IP, o.ObservedAt).Scan(&leaseEndpoint)
		if err == sql.ErrNoRows || leaseEndpoint != endpointID {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	kind := "passive_event_time_identity"
	if o.Origin == "arp" {
		kind = "passive_arp_sender_identity"
	}
	basis, _ := json.Marshal(map[string]any{"kind": kind, "sensor": o.Node, "ip": o.IP, "mac": mac, "origin": o.Origin})
	return &passiveLinkRow{ObservationID: o.ID, EndpointID: endpointID, ValidUntil: o.ValidUntil, Basis: basis}, nil
}

// insertPassiveLinksBatch writes one batch of identity links in endpoint order.
// The join replaces the previous per-observation endpoint existence probe. One
// fact now refreshes the same link row many times, so the conflict update only
// runs when the endpoint changes or the validity extends by five minutes; the
// recognition/profile triggers therefore do not fire for every repeated frame.
func (s *DBStore) insertPassiveLinksBatch(ctx context.Context, db passiveDiscoveryDB, links []passiveLinkRow) error {
	if len(links) == 0 {
		return nil
	}
	// One fact can appear several times in a batch; ON CONFLICT may not touch
	// the same row twice, so keep the newest validity per observation first.
	deduped := make(map[string]passiveLinkRow, len(links))
	for _, link := range links {
		if previous, ok := deduped[link.ObservationID]; !ok || link.ValidUntil.After(previous.ValidUntil) {
			deduped[link.ObservationID] = link
		}
	}
	links = links[:0]
	for _, link := range deduped {
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].EndpointID == links[j].EndpointID {
			return links[i].ObservationID < links[j].ObservationID
		}
		return links[i].EndpointID < links[j].EndpointID
	})
	raw, err := json.Marshal(links)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `WITH incoming AS (
 SELECT * FROM jsonb_to_recordset($1::jsonb) AS r(observation_id text,endpoint_id text,valid_until timestamptz,basis jsonb)
)
INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis)
SELECT i.observation_id,i.endpoint_id,i.valid_until,i.basis
FROM incoming i JOIN endpoint_entities e ON e.endpoint_id=i.endpoint_id AND e.entity_role='endpoint'
ORDER BY i.endpoint_id,i.observation_id
ON CONFLICT(observation_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,valid_until=EXCLUDED.valid_until,basis=EXCLUDED.basis
WHERE discovery_identity_links.endpoint_id IS DISTINCT FROM EXCLUDED.endpoint_id OR discovery_identity_links.basis IS DISTINCT FROM EXCLUDED.basis OR EXCLUDED.valid_until>discovery_identity_links.valid_until+interval '5 minutes'`, string(raw))
	return err
}

// Only a multicast PTR answer with a MAC logged from that responder's own
// frame may establish a service-to-endpoint link without a DHCP lease.
func passiveDirectResponderIdentity(o discovery.Observation) bool {
	if o.Origin != "dns_sd" || o.Evidence.Source != "zeek" ||
		passiveString(o.Evidence.Payload, "service_source") != "ptr_responder" ||
		o.Evidence.Payload["l2_source_mac_direct"] != true ||
		validPassiveMAC(passiveString(o.Evidence.Payload, "responder_l2_mac")) != validPassiveMAC(o.MAC) ||
		validPassiveMAC(o.MAC) == "" || validPassiveMAC(passiveString(o.Evidence.Subject, "mac")) != validPassiveMAC(o.MAC) ||
		passiveString(o.Evidence.Subject, "ip") != o.IP {
		return false
	}
	destination, err := netip.ParseAddr(passiveString(o.Evidence.Flow, "dst_ip"))
	return err == nil && destination.IsMulticast()
}

func (s *DBStore) processPassiveDiscoveryBatch(ctx context.Context, events []normalized.Event, scope passiveDiscoveryScope) (passiveDiscoveryBatchStats, error) {
	stats := passiveDiscoveryBatchStats{Protocols: map[string]int{}, Reasons: map[string]int{}}
	started := time.Now()
	sections := map[string]time.Duration{}
	measure := func(name string, fn func() error) error {
		stage := time.Now()
		err := fn()
		sections[name] += time.Since(stage)
		discovery.ObserveStage(ctx, name, stage, err)
		return err
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return stats, err
	}
	defer tx.Rollback()
	if err := measure("arp_candidates", func() error { return ensurePassiveARPCandidateEndpoints(ctx, tx, events, scope) }); err != nil {
		return stats, err
	}
	coalescedMDNS := passiveCoalescedMDNSIndexes(events)
	coalescedARP := passiveCoalescedARPIndexes(events)
	pendingARP := make([]discovery.Observation, 0, len(events))
	pendingLinks := make([]passiveLinkRow, 0, len(events))
	pendingIDs := make(map[string]int)
	flushARP := func() error {
		if len(pendingARP) == 0 {
			return nil
		}
		if err := measure("arp_batch", func() error { return s.insertPassiveARPBatch(ctx, tx, pendingARP) }); err != nil {
			return err
		}
		pendingARP = pendingARP[:0]
		clear(pendingIDs)
		return nil
	}
	for index, event := range events {
		stats.Processed++
		stats.Protocols[event.SourceEventType]++
		if coalescedARP[index] {
			stats.Skipped++
			stats.Reasons["arp_repeated_claim_coalesced"]++
			continue
		}
		if coalescedMDNS[index] {
			stats.Skipped++
			stats.Reasons["mdns_repeated_record_coalesced"]++
			continue
		}
		if event.SourceEventType == "arp" {
			observation, reason := passiveObservation(event, scope)
			if reason != "" {
				stats.Skipped++
				stats.Reasons[reason]++
				continue
			}
			// A repeated fact row in the same statement would make PostgreSQL's
			// ON CONFLICT affect one row twice. Keep the newest claim for the
			// fact instead of writing the same row twice.
			if index, exists := pendingIDs[observation.ID]; exists {
				pendingARP[index] = observation
				stats.Skipped++
				stats.Reasons["arp_fact_refreshed"]++
				continue
			}
			pendingIDs[observation.ID] = len(pendingARP)
			pendingARP = append(pendingARP, observation)
			stats.Emitted++
			continue
		}
		if err := flushARP(); err != nil {
			return stats, err
		}
		var observations []discovery.Observation
		var reason string
		var eventErr error
		if event.SourceEventType == "mdns" {
			stage := time.Now()
			observations, reason, eventErr = s.materializeMDNS(ctx, tx, event, scope)
			sections["mdns"] += time.Since(stage)
			discovery.ObserveStage(ctx, "mdns", stage, eventErr)
		} else {
			var observation discovery.Observation
			observation, reason = passiveObservation(event, scope)
			if reason == "" {
				observations = []discovery.Observation{observation}
			}
		}
		if eventErr != nil {
			return stats, eventErr
		}
		if reason != "" {
			stats.Skipped++
			stats.Reasons[reason]++
			continue
		}
		for _, observation := range observations {
			stage := time.Now()
			link, linkErr := s.insertPassiveObservation(ctx, tx, observation)
			sections["observe"] += time.Since(stage)
			discovery.ObserveStage(ctx, "observe", stage, linkErr)
			if linkErr != nil {
				return stats, linkErr
			}
			if link != nil {
				pendingLinks = append(pendingLinks, *link)
			}
			stats.Emitted++
		}
	}
	if err := flushARP(); err != nil {
		return stats, err
	}
	if err := measure("link_batch", func() error { return s.insertPassiveLinksBatch(ctx, tx, pendingLinks) }); err != nil {
		return stats, err
	}
	commitStage := time.Now()
	err = tx.Commit()
	sections["commit"] += time.Since(commitStage)
	discovery.ObserveStage(ctx, "commit", commitStage, err)
	logSlowPassiveBatch(stats, sections, time.Since(started))
	return stats, err
}

func (s *DBStore) finishPassiveDiscovery(ctx context.Context, sensorID string, cursor passiveDiscoveryCursor, stats passiveDiscoveryBatchStats, runErr error) error {
	if runErr != nil {
		_, err := s.pg.db.ExecContext(ctx, `UPDATE passive_discovery_state SET lease_owner='',lease_until='-infinity',last_error=$3,updated_at=now() WHERE sensor_id=$1 AND lease_owner=$2`, sensorID, cursor.Owner, runErr.Error())
		return err
	}
	protocols, _ := json.Marshal(stats.Protocols)
	reasons, _ := json.Marshal(stats.Reasons)
	_, err := s.pg.db.ExecContext(ctx, `UPDATE passive_discovery_state SET cursor_timestamp=$3,cursor_event_id=$4,processed_events=processed_events+$5,emitted_observations=emitted_observations+$6,skipped_events=skipped_events+$7,
protocol_counts=coalesce((SELECT jsonb_object_agg(key,total) FROM (SELECT key,sum(value::bigint) total FROM (SELECT * FROM jsonb_each_text(protocol_counts) UNION ALL SELECT * FROM jsonb_each_text($8::jsonb)) counts GROUP BY key) totals),'{}'::jsonb),
skip_counts=coalesce((SELECT jsonb_object_agg(key,total) FROM (SELECT key,sum(value::bigint) total FROM (SELECT * FROM jsonb_each_text(skip_counts) UNION ALL SELECT * FROM jsonb_each_text($9::jsonb)) counts GROUP BY key) totals),'{}'::jsonb),
lease_owner='',lease_until='-infinity',last_success_at=now(),last_error='',updated_at=now() WHERE sensor_id=$1 AND lease_owner=$2`, sensorID, cursor.Owner, cursor.Timestamp, cursor.EventID, stats.Processed, stats.Emitted, stats.Skipped, protocols, reasons)
	if err != nil {
		return err
	}
	// The cursor has advanced. The runtime beacon is only a status hint, so a
	// slow beacon must not turn a committed batch into a reported failure and
	// force the same batch through the pipeline again.
	state, _ := json.Marshal(map[string]any{"status": "ready", "sensor_id": sensorID, "cursor_at": cursor.Timestamp, "processed": stats.Processed, "emitted": stats.Emitted, "skipped": stats.Skipped, "protocols": stats.Protocols, "skip_reasons": stats.Reasons})
	if _, beaconErr := s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('passive-discovery',$1,now()) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, state); beaconErr != nil {
		fmt.Fprintf(os.Stderr, "passive discovery beacon: %v\n", beaconErr)
	}
	return nil
}

func (s *DBStore) runPassiveDiscoveryMaterializer(ctx context.Context, sensorID string) {
	// Snapshot development can exercise recognition without replaying discovery.
	if os.Getenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_DISABLED") == "true" {
		return
	}
	observer := discovery.NewPipelineObserver()
	ctx = discovery.WithPipelineObserver(ctx, observer)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			probe, stop := context.WithTimeout(ctx, 2*time.Second)
			err := observer.Flush(probe, s.pg.db, sensorID+"/dhcp", "dhcp", "passive")
			stop()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "passive discovery heartbeat:", discovery.WorkErrorCode(err))
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	defer func() { <-heartbeatDone }()
	owner := fmt.Sprintf("passive-discovery-%d", os.Getpid())
	batchTuner := passiveDiscoveryBatchTuner{limit: passiveDiscoveryBatchSize}
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		requestedLimit := batchTuner.limit
		scope, err := parsePassiveDiscoveryScope(os.Getenv("PROXY_SENTINEL_DISCOVERY_CIDRS"))
		claimed := false
		batchEvents := 0
		batchTruncated := false
		processedEvents := 0
		stageStarted := time.Now()
		if err == nil {
			var cursor passiveDiscoveryCursor
			cursor, claimed, err = s.claimPassiveDiscovery(workCtx, sensorID, owner)
			if err == nil && claimed {
				var events []normalized.Event
				var next passiveDiscoveryCursor
				events, next, batchTruncated, err = s.passiveDiscoveryEvents(workCtx, sensorID, cursor, requestedLimit)
				discovery.ObserveStage(workCtx, "dhcp_read", stageStarted, err)
				stageStarted = time.Now()
				batchEvents = len(events)
				stats := passiveDiscoveryBatchStats{Protocols: map[string]int{}, Reasons: map[string]int{}}
				if err == nil && len(events) > 0 {
					passiveBatchMu.Lock()
					stats, err = s.processPassiveDiscoveryBatch(workCtx, events, scope)
					passiveBatchMu.Unlock()
				}
				if err == nil {
					cursor = next
				}
				finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(workCtx), 8*time.Second)
				finishErr := s.finishPassiveDiscovery(finishCtx, sensorID, cursor, stats, err)
				finishCancel()
				if err == nil {
					err = finishErr
				}
				if err == nil {
					processedEvents = stats.Processed
				}
				discovery.ObserveStage(workCtx, "dhcp_publish", stageStarted, err)
			}
		}
		discovery.RecordPipelineResult(workCtx, processedEvents, err, "dhcp")
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "passive discovery materialize failed: %s\n", discovery.WorkErrorCode(err))
			state, _ := json.Marshal(map[string]any{"status": "error", "error": err.Error(), "sensor_id": sensorID})
			reportCtx, reportCancel := context.WithTimeout(context.WithoutCancel(workCtx), 2*time.Second)
			_, _ = s.pg.db.ExecContext(reportCtx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('passive-discovery',$1,now()) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, state)
			reportCancel()
		}
		cancel()
		fullBatch := batchEvents >= requestedLimit || batchTruncated
		if claimed {
			batchTuner.observe(fullBatch, err)
		}
		delay := 5 * time.Second
		if claimed && err == nil && fullBatch {
			delay = 0
		} else if claimed && err == nil {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// RunPassiveDiscoveryMaterializer provides the dedicated worker entry point.
// The same persisted cursor and lease prevent duplicate concurrent consumption.
func (s *DBStore) RunPassiveDiscoveryMaterializer(ctx context.Context, sensorID string) {
	if os.Getenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_DISABLED") == "true" {
		return
	}
	liveDone := make(chan struct{})
	go func() {
		defer close(liveDone)
		s.runPassiveLivePTRMaterializer(ctx, sensorID)
	}()
	s.runPassiveDiscoveryMaterializer(ctx, sensorID)
	<-liveDone
}
