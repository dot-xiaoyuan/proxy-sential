package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
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

func (s *DBStore) passiveDiscoveryEvents(ctx context.Context, sensorID string, cursor passiveDiscoveryCursor, limit int) ([]normalized.Event, passiveDiscoveryCursor, error) {
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	where := "sensor_id=" + chQuote(sensorID) + " AND (timestamp,event_id)>(parseDateTime64BestEffort(" + chQuote(cursor.Timestamp.UTC().Format(time.RFC3339Nano)) + ",6)," + chQuote(cursor.EventID) + ")"
	where += " AND source_event_type IN ('dhcp','arp','ndp','mdns','ssdp','ws_discovery','lldp','cdp','ieee1905_client_association')"
	query := fmt.Sprintf(`SELECT formatDateTime(timestamp,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') event_timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence FROM passive_discovery_events_v1 PREWHERE %s ORDER BY timestamp,event_id LIMIT %d SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`, where, limit)
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return nil, cursor, err
	}
	rows := []passiveDiscoveryRow{}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return nil, cursor, err
	}
	events := make([]normalized.Event, 0, len(rows))
	next := cursor
	for _, row := range rows {
		stamp, parseErr := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.Timestamp))
		if parseErr != nil {
			return nil, cursor, parseErr
		}
		event := normalized.Event{SchemaVersion: "v1", EventID: row.EventID, Source: row.Source, SourceEventType: row.SourceEventType, Type: row.Type, Timestamp: stamp.UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": row.SensorID}, Subject: map[string]any{"ip": row.SubjectIP, "mac": row.SubjectMAC, "campus_id": row.CampusID}, Payload: map[string]any{}, Flow: map[string]any{}, Confidence: row.Confidence}
		_ = json.Unmarshal([]byte(row.ObserverJSON), &event.Observer)
		_ = json.Unmarshal([]byte(row.PayloadJSON), &event.Payload)
		_ = json.Unmarshal([]byte(row.FlowJSON), &event.Flow)
		event.Observer["sensor_id"] = row.SensorID
		events = append(events, event)
		next.Timestamp, next.EventID = stamp.UTC(), row.EventID
	}
	return events, next, nil
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
		if o.Name == "" {
			o.Name = passiveString(event.Payload, "hostname")
		}
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
	case "ssdp":
		if !scope.allows(ip) {
			return discovery.Observation{}, "ssdp_out_of_scope"
		}
		service := strings.ToLower(passiveString(event.Payload, "st") + " " + passiveString(event.Payload, "nt"))
		o.Origin, o.Explanation, o.ValidUntil = "ssdp", "SSDP 设备响应或公告", at.Add(30*time.Minute)
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
	return o, ""
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
	observation := discovery.Observation{ID: evidence.EventID, EventID: evidence.EventID, SourceID: "passive:" + sensor + ":" + iface, Node: sensor, Site: passiveString(event.Subject, "campus_id"), Domain: passiveString(event.Payload, "access_domain"), IP: address, Name: name, Origin: "dns_sd", DeviceType: passivePrinterType(capabilities, instance), Capabilities: capabilities, Confidence: "strong", Explanation: "DNS-SD 服务响应由报文源地址被动关联", RuleVersion: discovery.RuleVersion, ObservedAt: at, ValidUntil: validUntil, Interface: iface, Evidence: evidence}
	if observation.Site == "" {
		observation.Site = sensor
	}
	if observation.Domain == "" {
		observation.Domain = iface
	}
	return observation, true
}

func (s *DBStore) materializeMDNS(ctx context.Context, event normalized.Event, scope passiveDiscoveryScope) ([]discovery.Observation, string, error) {
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
	raw, _ := json.Marshal(event.Payload)
	if ttl == 0 {
		_, err = s.pg.db.ExecContext(ctx, `DELETE FROM passive_discovery_mdns_records WHERE sensor_id=$1 AND interface_name=$2 AND record_name=$3 AND record_type=$4 AND record_value=$5`, sensor, iface, recordName, recordType, value)
		if err == nil {
			switch recordType {
			case "A", "AAAA":
				_, err = s.pg.db.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1),withdrawn=true WHERE origin='dns_sd' AND source_id=$2 AND data->>'ip'=$3 AND observed_at<=$1`, at, "passive:"+sensor+":"+iface, value)
			case "SRV", "TXT":
				_, err = s.pg.db.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1),withdrawn=true WHERE origin='dns_sd' AND source_id=$2 AND data->'evidence'->'payload'->>'service_instance'=$3 AND observed_at<=$1`, at, "passive:"+sensor+":"+iface, recordName)
			case "PTR":
				_, err = s.pg.db.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1),withdrawn=true WHERE origin='dns_sd' AND source_id=$2 AND data->'evidence'->'payload'->>'service_instance'=$3 AND observed_at<=$1`, at, "passive:"+sensor+":"+iface, value)
			}
		}
	} else {
		_, err = s.pg.db.ExecContext(ctx, `INSERT INTO passive_discovery_mdns_records(sensor_id,interface_name,record_name,record_type,record_value,observed_at,valid_until,event_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(sensor_id,interface_name,record_name,record_type,record_value) DO UPDATE SET observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,event_id=EXCLUDED.event_id,payload=EXCLUDED.payload WHERE EXCLUDED.observed_at>=passive_discovery_mdns_records.observed_at`, sensor, iface, recordName, recordType, value, at, validUntil, event.EventID, raw)
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
	rows, err := s.pg.db.QueryContext(ctx, `SELECT srv.record_name,srv.record_value,addr.record_value,least(srv.valid_until,addr.valid_until),coalesce(txt.record_value,''),greatest(srv.observed_at,addr.observed_at),srv.event_id
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
		o := discovery.Observation{ID: evidence.EventID, EventID: evidence.EventID, SourceID: "passive:" + sensor + ":" + iface, Node: sensor, Site: passiveString(event.Subject, "campus_id"), Domain: passiveString(event.Payload, "access_domain"), IP: address, Name: name, Origin: "dns_sd", DeviceType: deviceType, Capabilities: capabilities, Confidence: "strong", Explanation: "DNS-SD 服务响应与地址记录自动关联", RuleVersion: discovery.RuleVersion, ObservedAt: observed, ValidUntil: until, Interface: iface, Evidence: evidence}
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

func (s *DBStore) insertPassiveObservation(ctx context.Context, o discovery.Observation) error {
	if o.ID == "" || o.ObservedAt.IsZero() {
		return nil
	}
	if o.ValidUntil.IsZero() {
		o.ValidUntil = o.ObservedAt.Add(24 * time.Hour)
	}
	// Service advertisements usually carry an IP but no MAC. Reuse only an
	// event-time DHCP/ARP/NDP binding; never manufacture a terminal identity.
	if o.MAC == "" && o.IP != "" {
		var mac string
		err := s.pg.db.QueryRowContext(ctx, `SELECT lower(data->>'mac')
FROM discovery_observations
WHERE data->>'node'=$1 AND data->>'ip'=$2 AND coalesce(data->>'mac','')<>''
  AND origin IN ('dhcp','arp','ndp') AND observed_at<=$3 AND valid_until>$3
ORDER BY observed_at DESC,id DESC LIMIT 1`, o.Node, o.IP, o.ObservedAt).Scan(&mac)
		if err == nil {
			o.MAC = validPassiveMAC(mac)
		} else if err != sql.ErrNoRows {
			return err
		}
	}
	raw, _ := json.Marshal(o)
	if _, err := s.pg.db.ExecContext(ctx, `INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO NOTHING`, o.ID, o.Key(), o.SourceID, o.Origin, o.ObservedAt, o.ValidUntil, o.Withdrawn, raw); err != nil {
		return err
	}
	return s.linkPassiveObservation(ctx, o)
}

func (s *DBStore) linkPassiveObservation(ctx context.Context, o discovery.Observation) error {
	mac := validPassiveMAC(o.MAC)
	if mac == "" {
		return nil
	}
	if passiveRandomMAC(mac) && o.IP == "" {
		return nil
	}
	endpointID := "mac:" + mac
	var exists bool
	if err := s.pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM endpoint_entities WHERE endpoint_id=$1 AND entity_role='endpoint')`, endpointID).Scan(&exists); err != nil || !exists {
		return err
	}
	if o.IP != "" {
		var leaseEndpoint string
		err := s.pg.db.QueryRowContext(ctx, `SELECT endpoint_id FROM device_address_leases WHERE sensor_id=$1 AND campus_id=$2 AND ip=$3::inet AND action='ack' AND observed_at<=$4 AND valid_until>$4 ORDER BY observed_at DESC,event_id DESC LIMIT 1`, o.Node, passiveString(o.Evidence.Subject, "campus_id"), o.IP, o.ObservedAt).Scan(&leaseEndpoint)
		if err == sql.ErrNoRows || leaseEndpoint != endpointID {
			return nil
		}
		if err != nil {
			return err
		}
	}
	basis, _ := json.Marshal(map[string]any{"kind": "passive_event_time_identity", "sensor": o.Node, "ip": o.IP, "mac": mac})
	_, err := s.pg.db.ExecContext(ctx, `INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis) VALUES($1,$2,$3,$4) ON CONFLICT(observation_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,valid_until=EXCLUDED.valid_until,basis=EXCLUDED.basis`, o.ID, endpointID, o.ValidUntil, basis)
	return err
}

func (s *DBStore) processPassiveDiscoveryBatch(ctx context.Context, events []normalized.Event, scope passiveDiscoveryScope) (passiveDiscoveryBatchStats, error) {
	stats := passiveDiscoveryBatchStats{Protocols: map[string]int{}, Reasons: map[string]int{}}
	for _, event := range events {
		stats.Processed++
		stats.Protocols[event.SourceEventType]++
		var observations []discovery.Observation
		var reason string
		var err error
		if event.SourceEventType == "mdns" {
			observations, reason, err = s.materializeMDNS(ctx, event, scope)
		} else {
			var observation discovery.Observation
			observation, reason = passiveObservation(event, scope)
			if reason == "" {
				observations = []discovery.Observation{observation}
			}
		}
		if err != nil {
			return stats, err
		}
		if reason != "" {
			stats.Skipped++
			stats.Reasons[reason]++
			continue
		}
		for _, observation := range observations {
			if err = s.insertPassiveObservation(ctx, observation); err != nil {
				return stats, err
			}
			stats.Emitted++
		}
	}
	return stats, nil
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
	if err == nil {
		state, _ := json.Marshal(map[string]any{"status": "ready", "sensor_id": sensorID, "cursor_at": cursor.Timestamp, "processed": stats.Processed, "emitted": stats.Emitted, "skipped": stats.Skipped, "protocols": stats.Protocols, "skip_reasons": stats.Reasons})
		_, err = s.pg.db.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('passive-discovery',$1,now()) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, state)
	}
	return err
}

func (s *DBStore) runPassiveDiscoveryMaterializer(ctx context.Context, sensorID string) {
	owner := fmt.Sprintf("passive-discovery-%d", os.Getpid())
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		scope, err := parsePassiveDiscoveryScope(os.Getenv("PROXY_SENTINEL_DISCOVERY_CIDRS"))
		claimed := false
		if err == nil {
			var cursor passiveDiscoveryCursor
			cursor, claimed, err = s.claimPassiveDiscovery(workCtx, sensorID, owner)
			if err == nil && claimed {
				var events []normalized.Event
				var next passiveDiscoveryCursor
				events, next, err = s.passiveDiscoveryEvents(workCtx, sensorID, cursor, 2000)
				stats := passiveDiscoveryBatchStats{Protocols: map[string]int{}, Reasons: map[string]int{}}
				if err == nil && len(events) > 0 {
					stats, err = s.processPassiveDiscoveryBatch(workCtx, events, scope)
				}
				if err == nil {
					cursor = next
				}
				if finishErr := s.finishPassiveDiscovery(context.WithoutCancel(workCtx), sensorID, cursor, stats, err); err == nil {
					err = finishErr
				}
			}
		}
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "passive discovery materialize failed: %v\n", err)
			state, _ := json.Marshal(map[string]any{"status": "error", "error": err.Error(), "sensor_id": sensorID})
			_, _ = s.pg.db.ExecContext(context.WithoutCancel(workCtx), `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('passive-discovery',$1,now()) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, state)
		}
		cancel()
		delay := 5 * time.Second
		if claimed && err == nil {
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
