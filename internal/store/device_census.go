package store

import (
	"context"
	"fmt"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

// DeviceCensus answers the coverage question that has to be settled before any
// recognition rule is added: how many physical devices the mirror can observe
// at all, and how many of them already carry a recognised profile. It is
// read-only and safe to run repeatedly against a production sensor.
type DeviceCensus struct {
	SensorID      string `json:"sensor_id"`
	WindowSeconds int    `json:"window_seconds"`
	AsOf          string `json:"as_of"`
	// Denominator: physical devices that produced at least one event. It stays
	// at zero until link-layer attribution is available, which is the finding
	// this report exists to surface.
	ObservedMACs int `json:"observed_macs"`
	ObservedIPs  int `json:"observed_ips"`
	// Devices holding a DHCP lease observed inside the window.
	LeasedDevices int `json:"leased_devices"`
	// Recognised profiles plus per-source visibility. The embedded summary
	// keeps its own fixed twenty-four hour window.
	Recognition DeviceRecognitionSummary `json:"recognition"`
	// Partial failures are reported instead of aborting the whole report.
	Errors []string `json:"errors,omitempty"`
}

func (s *DBStore) GetDeviceCensus(ctx context.Context, window time.Duration) (DeviceCensus, error) {
	if window <= 0 {
		window = 24 * time.Hour
	}
	seconds := int(window.Seconds())
	census := DeviceCensus{SensorID: s.pg.sensorID, WindowSeconds: seconds, AsOf: time.Now().UTC().Format(time.RFC3339Nano)}
	// uniqExact over subject_mac answers how many devices the mirror actually
	// exposed. Distinct source addresses are reported separately because one
	// address can carry several devices and one device can change address.
	// Both are scoped to this sensor so the report matches its lease count.
	for _, item := range []struct {
		name string
		sql  string
		into *int
	}{
		{
			name: "observed_macs",
			sql:  fmt.Sprintf(`SELECT uniqExact(subject_mac) AS value FROM normalized_events PREWHERE sensor_id=%s AND timestamp>=now()-INTERVAL %d SECOND AND subject_mac!='' FORMAT JSONEachRow`, chQuote(s.pg.sensorID), seconds),
			into: &census.ObservedMACs,
		},
		{
			name: "observed_ips",
			sql:  fmt.Sprintf(`SELECT uniqExact(subject_ip) AS value FROM normalized_events PREWHERE sensor_id=%s AND timestamp>=now()-INTERVAL %d SECOND AND subject_ip!='' FORMAT JSONEachRow`, chQuote(s.pg.sensorID), seconds),
			into: &census.ObservedIPs,
		},
	} {
		raw, err := s.ch.query(ctx, item.sql)
		if err != nil {
			census.Errors = append(census.Errors, item.name+": "+err.Error())
			continue
		}
		var rows []struct {
			Value int `json:"value"`
		}
		if err := decodeJSONEachRow(raw, &rows); err != nil {
			census.Errors = append(census.Errors, item.name+": "+err.Error())
			continue
		}
		if len(rows) > 0 {
			*item.into = rows[0].Value
		}
	}
	var leased int
	if err := s.pg.db.QueryRowContext(ctx, `SELECT count(DISTINCT endpoint_id) FROM device_address_leases WHERE sensor_id=$1 AND action='ack' AND valid_until>now() AND observed_at>=now()-make_interval(secs=>$2::double precision)`, s.pg.sensorID, seconds).Scan(&leased); err != nil {
		census.Errors = append(census.Errors, "leased_devices: "+err.Error())
	} else {
		census.LeasedDevices = leased
	}
	summary, err := s.GetDeviceRecognitionSummary(ctx, fingerprint.Default().Version())
	if err != nil {
		census.Errors = append(census.Errors, "recognition: "+err.Error())
	} else {
		census.Recognition = summary
	}
	return census, nil
}
