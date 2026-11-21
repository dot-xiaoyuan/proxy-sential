package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

type deviceLease struct {
	Sensor, Campus, EventID, IP, Endpoint, Action string
	At, Until                                     time.Time
}

func deviceLeaseFromEvent(e normalized.Event) (deviceLease, bool) {
	l := deviceLease{}
	if stringFromMap(e.Payload, "origin") != "dhcp" {
		return l, false
	}
	perMessage := e.Source == "zeek" && stringFromMap(e.RawRef, "log") == "device_dhcp_message"
	// The per-message adapter keeps withdrawals out of device discovery.
	// An explicit withdrawal can still terminate a lease for that MAC and IP.
	if e.Type != "device" {
		if e.Type != "dhcp_message" || !perMessage {
			return l, false
		}
		switch strings.ToUpper(stringFromMap(e.Payload, "msg_types")) {
		case "RELEASE", "NAK", "DECLINE":
		default:
			return l, false
		}
	}
	if conflict, _ := e.Payload["discovery_scope_conflict"].(bool); conflict {
		return l, false
	}
	l.Sensor = stringFromMap(e.Observer, "sensor_id")
	l.Campus = stringFromMap(e.Subject, "campus_id")
	l.EventID = e.EventID
	l.IP = stringFromMap(e.Subject, "ip")
	mac, err := net.ParseMAC(stringFromMap(e.Subject, "mac"))
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return l, false
	}
	l.Endpoint = "mac:" + mac.String()
	if l.Sensor == "" || l.EventID == "" || net.ParseIP(l.IP) == nil || net.ParseIP(l.IP).IsUnspecified() {
		return l, false
	}
	// The timestamp of a single message is its observation time. Aggregated ACKs
	// need an explicit ACK time because their timestamp can be from discovery.
	at := stringFromMap(e.Payload, "lease_observed_at")
	if at == "" {
		if !perMessage && strings.Contains(strings.ToUpper(stringFromMap(e.Payload, "msg_types")), "ACK") {
			return l, false
		}
		at = e.Timestamp
	}
	l.At, err = time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return l, false
	}
	types := strings.Split(strings.ToUpper(stringFromMap(e.Payload, "msg_types")), ",")
	ack, stop := false, false
	for _, v := range types {
		switch strings.TrimSpace(v) {
		case "ACK":
			ack = true
		case "RELEASE", "NAK", "DECLINE":
			stop = true
		}
	}
	if stop {
		l.Action = "stop"
		l.Until = l.At
		return l, true
	}
	if !ack || stringFromMap(e.Payload, "assigned_addr") != l.IP {
		return l, false
	}
	seconds, err := strconv.ParseFloat(fmt.Sprint(e.Payload["lease_time"]), 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > 7*24*3600 {
		return l, false
	}
	l.Action = "ack"
	l.Until = l.At.Add(time.Duration(seconds * float64(time.Second)))
	return l, true
}

type deviceLeaseExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// writeDeviceLeases writes every lease the batch carries in one statement.
func writeDeviceLeases(ctx context.Context, db deviceLeaseExecutor, events []normalized.Event) error {
	leases := make([]deviceLease, 0, len(events))
	for _, e := range events {
		if l, ok := deviceLeaseFromEvent(e); ok {
			leases = append(leases, l)
		}
	}
	return insertDeviceLeasesBatch(ctx, db, leases)
}

// ResolveDeviceAt only assigns a physical endpoint; it never assigns an account.
// A later ACK supersedes earlier leases, while simultaneous disagreeing ACKs conflict.
func (s *PostgresStore) ResolveDeviceAt(ctx context.Context, o DomainObservation) (IdentityAttribution, bool, error) {
	// An observation without an address cannot match a lease. Casting '' to inet raised
	// 51,834 errors on the field, each aborting the caller's batch.
	if o.SensorID == "" || strings.TrimSpace(o.IP) == "" {
		return IdentityAttribution{}, false, nil
	}
	at, err := time.Parse(time.RFC3339Nano, o.Timestamp)
	if err != nil {
		return IdentityAttribution{}, false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT l.endpoint_id FROM device_address_leases l
 WHERE l.sensor_id=$1 AND l.campus_id=$2 AND l.ip=$3::inet AND l.action='ack'
 AND l.observed_at<=$4 AND l.valid_until>$4
 AND NOT EXISTS (SELECT 1 FROM device_address_leases n WHERE n.sensor_id=l.sensor_id AND n.campus_id=l.campus_id AND n.ip=l.ip AND n.observed_at<=$4 AND ((n.action='ack' AND n.observed_at>l.observed_at) OR (n.action='stop' AND n.endpoint_id=l.endpoint_id AND n.observed_at>=l.observed_at)))
 ORDER BY l.endpoint_id LIMIT 2`, o.SensorID, o.CampusID, o.IP, at)
	if err != nil {
		return IdentityAttribution{}, false, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return IdentityAttribution{}, false, err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return IdentityAttribution{}, false, err
	}
	if len(ids) == 0 {
		return IdentityAttribution{}, false, nil
	}
	r := IdentityAttribution{EndpointID: ids[0]}
	if len(ids) > 1 {
		r.Conflict = true
		r.ConflictReason = "同一传感器和园区存在冲突 DHCP 租约"
	}
	return r, true, nil
}
