package legacy4k

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Event struct {
	Action          int    `json:"action"`
	SessionID       string `json:"session_id"`
	NASIP           string `json:"nas_ip"`
	UserName        string `json:"user_name"`
	IP              string `json:"ip"`
	IPv6            string `json:"ip6"`
	UserMAC         string `json:"user_mac"`
	NASPortID       string `json:"nas_port_id"`
	CalledStationID string `json:"called_station_id"`
	VLANID          string `json:"vlan_id"`
	DeviceID        string `json:"device_id"`
	OSName          string `json:"os_name"`
	ClassName       string `json:"class_name"`
	AddTime         int64  `json:"add_time"`
	DropTime        int64  `json:"drop_time"`
}

func DecodeRecord(raw string, now time.Time) (map[string]string, error) {
	var event Event
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return nil, err
	}
	if event.UserName == "" || (event.IP == "" && event.IPv6 == "") {
		return nil, fmt.Errorf("legacy event requires user_name and ip")
	}
	action := "login"
	timestamp := event.AddTime
	if event.Action == 2 {
		action, timestamp = "logout", event.DropTime
	}
	if event.Action != 1 && event.Action != 2 {
		return nil, fmt.Errorf("unsupported legacy action %d", event.Action)
	}
	if timestamp <= 0 {
		timestamp = now.Unix()
	}
	ip := event.IP
	if ip == "" {
		ip = event.IPv6
	}
	record := map[string]string{"timestamp": time.Unix(timestamp, 0).UTC().Format(time.RFC3339Nano), "action": action, "account_id": event.UserName, "ip": ip, "mac": event.UserMAC, "session_id": event.SessionID, "nas_ip": event.NASIP, "nas_port_id": event.NASPortID, "access_id": event.CalledStationID, "vlan": event.VLANID, "endpoint_id": event.DeviceID, "os_name": event.OSName, "class_name": event.ClassName, "entity_role": "endpoint", "identity_confidence": "0.95"}
	for key, value := range record {
		if strings.TrimSpace(value) == "" {
			delete(record, key)
		}
	}
	return record, nil
}

func RecordFromHash(fields map[string]string, now time.Time) (map[string]string, error) {
	event := Event{Action: 1, SessionID: first(fields, "session_id", "rad_online_id"), NASIP: first(fields, "nas_ip"), UserName: first(fields, "user_name", "username"), IP: first(fields, "ip"), UserMAC: first(fields, "user_mac", "mac"), VLANID: first(fields, "vlan_id", "vlan"), DeviceID: first(fields, "device_id"), OSName: first(fields, "os_name"), ClassName: first(fields, "class_name")}
	if value, err := strconv.ParseInt(first(fields, "add_time"), 10, 64); err == nil {
		event.AddTime = value
	} else {
		event.AddTime = now.Unix()
	}
	raw, _ := json.Marshal(event)
	return DecodeRecord(string(raw), now)
}

type Sender struct {
	Endpoint, Token, SensorID string
	Client                    *http.Client
}

func (s Sender) Send(ctx context.Context, records []map[string]string, idempotency string) error {
	if len(records) == 0 {
		return nil
	}
	payload, err := json.Marshal(map[string]any{"source": "legacy-4k", "sensor_id": s.SensorID, "records": records})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.Endpoint, "/")+"/api/v1/integrations/identity/events", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+s.Token)
	request.Header.Set("Idempotency-Key", idempotency)
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("identity endpoint returned %s", response.Status)
	}
	return nil
}

func StableID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "legacy-4k-" + hex.EncodeToString(sum[:])[:24]
}
func first(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}
