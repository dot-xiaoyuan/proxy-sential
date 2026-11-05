// Package idevm converts IDevM registration rows into read-only facts. It does
// not call IDevM's registration, account, address-pool, or enforcement APIs.
package idevm

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// RegistrationRow is the subset of IDevM's users row needed to reconcile a
// registered device with passive evidence. Category IDs remain source IDs;
// they are not treated as Proxy Sentinel device types.
type RegistrationRow struct {
	UserID           int64  `json:"user_id"`
	UserName         string `json:"user_name"`
	UserRealName     string `json:"user_real_name"`
	MAC              string `json:"mac"`
	IP               string `json:"ip"`
	SN               string `json:"sn"`
	NASIP            string `json:"nas_ip"`
	NetAccessMethod  int    `json:"net_access_method"`
	DeviceTemplateID int64  `json:"device_template_id"`
	DeviceLocationID int64  `json:"device_location_id"`
	UserAvailable    int    `json:"user_available"`
	UserUpdateTime   int64  `json:"user_update_time"`
}

type RegistrationFact struct {
	SourceKey        string
	MAC              string
	RegisteredIP     string
	Name             string
	SerialNumber     string
	NASIP            string
	NetAccessMethod  int
	DeviceTemplateID int64
	DeviceLocationID int64
	AccessEnabled    bool
	UpdatedAt        time.Time
	MatchableByMAC   bool
}

// NormalizeRegistration keeps IDevM's registration and access state separate
// from observed online state. A static IP is registration data, never proof of
// the device's current address. 802.1X rows may have no MAC and stay unmatched.
func NormalizeRegistration(row RegistrationRow) (RegistrationFact, error) {
	if row.UserID <= 0 {
		return RegistrationFact{}, fmt.Errorf("idevm user_id must be positive")
	}
	if row.NetAccessMethod < 1 || row.NetAccessMethod > 5 {
		return RegistrationFact{}, fmt.Errorf("idevm net_access_method %d is invalid", row.NetAccessMethod)
	}
	result := RegistrationFact{
		SourceKey:        fmt.Sprintf("idevm:users:%d", row.UserID),
		Name:             strings.TrimSpace(row.UserRealName),
		SerialNumber:     strings.TrimSpace(row.SN),
		NetAccessMethod:  row.NetAccessMethod,
		DeviceTemplateID: row.DeviceTemplateID,
		DeviceLocationID: row.DeviceLocationID,
		AccessEnabled:    row.UserAvailable == 0,
	}
	// UserName is an access account, especially for 802.1X. It is not a
	// trustworthy device label when UserRealName is absent.
	if row.UserUpdateTime > 0 {
		result.UpdatedAt = time.Unix(row.UserUpdateTime, 0).UTC()
	}
	if raw := strings.TrimSpace(row.MAC); raw != "" {
		mac, err := net.ParseMAC(raw)
		if err != nil || len(mac) != 6 {
			return RegistrationFact{}, fmt.Errorf("idevm user_id %d has invalid MAC", row.UserID)
		}
		result.MAC = strings.ToLower(mac.String())
		result.MatchableByMAC = true
	}
	if raw := strings.TrimSpace(row.IP); raw != "" {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return RegistrationFact{}, fmt.Errorf("idevm user_id %d has invalid IP", row.UserID)
		}
		result.RegisteredIP = ip.String()
	}
	if raw := strings.TrimSpace(row.NASIP); raw != "" {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return RegistrationFact{}, fmt.Errorf("idevm user_id %d has invalid NAS IP", row.UserID)
		}
		result.NASIP = ip.String()
	}
	return result, nil
}
