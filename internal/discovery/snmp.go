package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"net"
	"proxy-sentinel/internal/normalized"
	"strconv"
	"strings"
	"time"
)

type Source struct {
	IdentitySensor string `json:"identity_sensor,omitempty"`
	IdentityCampus string `json:"identity_campus,omitempty"`
	IdentityVLAN   string `json:"identity_vlan,omitempty"`
	IdentityVRF    string `json:"identity_vrf,omitempty"`

	ID              string `json:"id"`
	Name            string `json:"name"`
	Node            string `json:"node"`
	Site            string `json:"site"`
	Domain          string `json:"domain"`
	VRF             string `json:"vrf,omitempty"`
	Address         string `json:"address"`
	Version         string `json:"snmp_version"`
	Username        string `json:"username,omitempty"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
	ConfigVersion   int    `json:"config_version"`
}
type Secret struct {
	Community string `json:"community,omitempty"`
	Auth      string `json:"auth,omitempty"`
	Privacy   string `json:"privacy,omitempty"`
}

func (s *Source) Validate() error {
	if strings.ContainsAny(s.ID, "/\\ ?#") {
		return fmt.Errorf("source ID contains unsupported characters")
	}
	if s.ID == "" || len(s.ID) > 100 || s.Node == "" || s.Site == "" || s.Domain == "" {
		return fmt.Errorf("source ID, node, site and network domain required")
	}
	if ip := net.ParseIP(s.Address); ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return fmt.Errorf("management address must be an IP")
	}
	if s.Version != "3" && s.Version != "2c" {
		return fmt.Errorf("SNMP version must be 3 or explicit 2c")
	}
	if s.Version == "3" && s.Username == "" {
		return fmt.Errorf("SNMPv3 username required")
	}
	if s.IntervalSeconds == 0 {
		s.IntervalSeconds = 300
	}
	if s.IntervalSeconds < 60 || s.IntervalSeconds > 86400 {
		return fmt.Errorf("poll interval must be 60..86400 seconds")
	}
	return nil
}

type TableStatus struct {
	Name     string `json:"name"`
	Count    int    `json:"count"`
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
}
type Snapshot struct {
	RejectedRecords int                `json:"rejected_records"`
	ID              string             `json:"id"`
	SourceID        string             `json:"source_id"`
	ConfigVersion   int                `json:"config_version"`
	At              time.Time          `json:"at"`
	Tables          []TableStatus      `json:"tables"`
	Events          []normalized.Event `json:"-"`
}
type Walker interface {
	Walk(string, gosnmp.WalkFunc) error
}

func Poll(ctx context.Context, s Source, secret Secret, id string) (Snapshot, error) {
	client := &gosnmp.GoSNMP{Target: s.Address, Port: 161, Timeout: 2 * time.Second, Retries: 1, Context: ctx, MaxRepetitions: 25, Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv}
	if s.Version == "2c" {
		if secret.Community == "" {
			return Snapshot{}, fmt.Errorf("SNMP community required")
		}
		client.Version = gosnmp.Version2c
		client.Community = secret.Community
	} else {
		if len(secret.Auth) < 8 || len(secret.Privacy) < 8 {
			return Snapshot{}, fmt.Errorf("SNMPv3 passphrases require at least 8 characters")
		}
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: s.Username, AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: secret.Auth, PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: secret.Privacy}
	}
	if err := client.Connect(); err != nil {
		return Snapshot{}, fmt.Errorf("SNMP connection failed")
	}
	defer client.Conn.Close()
	return PollTables(ctx, client, s, id, time.Now().UTC()), nil
}
func PollTables(ctx context.Context, w Walker, s Source, id string, now time.Time) Snapshot {
	out := Snapshot{ID: id, SourceID: s.ID, ConfigVersion: s.ConfigVersion, At: now, Tables: []TableStatus{}, Events: []normalized.Event{}}
	walk := func(name, root string) map[string]gosnmp.SnmpPDU {
		values := map[string]gosnmp.SnmpPDU{}
		err := w.Walk(root, func(p gosnmp.SnmpPDU) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(values) >= 100000 {
				return fmt.Errorf("table record limit")
			}
			key := strings.TrimPrefix(strings.TrimPrefix(p.Name, "."), strings.TrimPrefix(root, ".")+".")
			if key == p.Name {
				return fmt.Errorf("outside table")
			}
			values[key] = p
			return nil
		})
		st := TableStatus{Name: name, Count: len(values), Complete: err == nil}
		if err != nil {
			st.Error = "读取失败或超时；快照不完整"
		}
		if len(values) == 0 && err == nil {
			st.Error = "表未返回记录，请核实支持情况与读取权限"
		}
		out.Tables = append(out.Tables, st)
		return values
	}
	text := func(p gosnmp.SnmpPDU) string {
		if p.Value == nil {
			return ""
		}
		if b, ok := p.Value.([]byte); ok {
			return string(b)
		}
		return fmt.Sprint(p.Value)
	}
	integer := func(p gosnmp.SnmpPDU) string {
		if p.Value == nil {
			return ""
		}
		return gosnmp.ToBigInt(p.Value).String()
	}
	interfaces := walk("ifName", "1.3.6.1.2.1.31.1.1.1.1")
	bridge := walk("bridgePortIfIndex", "1.3.6.1.2.1.17.1.4.1.2")
	emit := func(origin, key, ip, mac, vlan, port string, extra map[string]any) {
		h := sha256.Sum256([]byte(id + ":" + origin + ":" + key))
		payload := map[string]any{"origin": origin, "ttl": s.IntervalSeconds * 3, "port": port}
		for k, v := range extra {
			payload[k] = v
		}
		event := normalized.Event{SchemaVersion: "v1", EventID: "discovery-" + hex.EncodeToString(h[:16]), Type: "discovery", Confidence: 0.5, Flow: map[string]any{"src_ip": "", "dst_ip": "", "proto": "other", "direction": "unknown"}, Source: "snmp", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"source_id": s.ID, "sensor_id": s.Node, "snapshot_id": id, "config_version": s.ConfigVersion}, Subject: map[string]any{"site": s.Site, "domain": s.Domain, "vrf": s.VRF, "vlan": vlan, "ip": ip, "mac": mac}, Payload: payload}
		if _, err := FromEvent(event); err != nil {
			out.RejectedRecords++
			return
		}
		out.Events = append(out.Events, event)
	}
	macSuffix := func(parts []string) string {
		if len(parts) != 6 {
			return ""
		}
		m := make(net.HardwareAddr, 6)
		for i, p := range parts {
			v, e := strconv.ParseUint(p, 10, 8)
			if e != nil {
				return ""
			}
			m[i] = byte(v)
		}
		return m.String()
	}
	// Q-BRIDGE FDB ID is NOT a VLAN ID. Resolve through dot1qVlanFdbId.
	vlanIDs := walk("vlanFdbId", "1.3.6.1.2.1.17.7.1.4.2.1.3")
	fdbVLAN := map[string][]string{}
	for key, p := range vlanIDs {
		parts := strings.Split(key, ".")
		if len(parts) >= 2 {
			fdb := integer(p)
			fdbVLAN[fdb] = append(fdbVLAN[fdb], parts[len(parts)-1])
		}
	}
	qfdb := walk("qBridgeFdbPort", "1.3.6.1.2.1.17.7.1.2.2.1.2")
	for key, p := range qfdb {
		parts := strings.Split(key, ".")
		if len(parts) != 7 {
			continue
		}
		vlans := fdbVLAN[parts[0]]
		vlan := ""
		if len(vlans) == 1 {
			vlan = vlans[0]
		}
		idx := integer(bridge[integer(p)])
		name := ""
		if v, ok := interfaces[idx]; ok {
			name = text(v)
		}
		emit("fdb", key, "", macSuffix(parts[1:]), vlan, name, map[string]any{"interface": idx, "location_kind": "path"})
	}
	if len(qfdb) == 0 {
		for key, p := range walk("bridgeFdbPort", "1.3.6.1.2.1.17.1.4.3.1.2") {
			idx := integer(bridge[integer(p)])
			name := ""
			if v, ok := interfaces[idx]; ok {
				name = text(v)
			}
			emit("fdb", key, "", macSuffix(strings.Split(key, ".")), "", name, map[string]any{"interface": idx, "location_kind": "path"})
		}
	}
	states := walk("ipNetToPhysicalState", "1.3.6.1.2.1.4.35.1.7")
	for key, p := range walk("ipNetToPhysicalPhysAddress", "1.3.6.1.2.1.4.35.1.4") {
		state := integer(states[key])
		if state == "5" || state == "7" {
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) < 4 {
			continue
		}
		length, e := strconv.Atoi(parts[2])
		if e != nil || len(parts) != length+3 || (length != 4 && length != 16) {
			continue
		}
		b := make(net.IP, length)
		good := true
		for i, v := range parts[3:] {
			n, e := strconv.ParseUint(v, 10, 8)
			if e != nil {
				good = false
				break
			}
			b[i] = byte(n)
		}
		m, ok := p.Value.([]byte)
		if good && ok && len(m) == 6 {
			emit("neighbor", key, b.String(), net.HardwareAddr(m).String(), "", "", map[string]any{"interface": parts[0]})
		}
	}
	for key, p := range walk("ipNetToMediaPhysAddress", "1.3.6.1.2.1.4.22.1.2") {
		parts := strings.Split(key, ".")
		m, ok := p.Value.([]byte)
		if len(parts) == 5 && ok && len(m) == 6 {
			emit("neighbor", "legacy."+key, strings.Join(parts[1:], "."), net.HardwareAddr(m).String(), "", "", map[string]any{"interface": parts[0]})
		}
	}
	caps := walk("lldpRemSysCapEnabled", "1.0.8802.1.1.2.1.4.1.1.12")
	chassis := walk("lldpRemChassisId", "1.0.8802.1.1.2.1.4.1.1.5")
	names := walk("lldpRemSysName", "1.0.8802.1.1.2.1.4.1.1.9")
	ports := walk("lldpRemPortId", "1.0.8802.1.1.2.1.4.1.1.7")
	for key, p := range chassis {
		capability := 0
		if b, ok := caps[key].Value.([]byte); ok && len(b) >= 2 {
			for bit := 0; bit < 16; bit++ {
				if b[bit/8]&(1<<uint(7-bit%8)) != 0 {
					capability |= 1 << uint(bit)
				}
			}
		}
		emit("lldp", key, "", "", "", "", map[string]any{"system_capabilities": capability, "chassis_id": text(p), "remote_port": text(ports[key]), "name": text(names[key]), "location_kind": "neighbor"})
	}
	return out
}
