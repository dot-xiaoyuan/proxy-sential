package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type inventoryCursor struct {
	Version   int    `json:"v"`
	Signature string `json:"s"`
	LastSeen  string `json:"t,omitempty"`
	Endpoint  string `json:"e"`
}

func inventoryQuerySignature(q Query) string {
	// Keep the signed fields limited to predicates and ordering. The cursor
	// itself is deliberately excluded so a token cannot be replayed for another
	// filter or sort order.
	type signatureQuery struct {
		View, Q, SensorID, CampusID, Department, PersonType string
		SSID, VLAN, AP, NASIP, Ecosystem, Brand, OSFamily   string
		Window, SrcIP, SearchType                           string
	}
	b, _ := json.Marshal(signatureQuery{
		View: q.View, Q: q.Q, SensorID: q.SensorID, CampusID: q.CampusID,
		Department: q.Department, PersonType: q.PersonType, SSID: q.SSID,
		VLAN: q.VLAN, AP: q.AP, NASIP: q.NASIP, Ecosystem: q.Ecosystem,
		Brand: q.Brand, OSFamily: q.OSFamily, Window: q.Window, SrcIP: q.SrcIP,
		SearchType: q.InventorySearchType,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func encodeInventoryCursor(q Query, lastSeen *time.Time, endpoint string) (string, error) {
	if endpoint == "" {
		return "", nil
	}
	c := inventoryCursor{Version: 1, Signature: inventoryQuerySignature(q), Endpoint: endpoint}
	if lastSeen != nil {
		c.LastSeen = lastSeen.UTC().Format(time.RFC3339Nano)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeInventoryCursor(q Query, raw string) (*inventoryCursor, error) {
	if raw == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid inventory cursor")
	}
	var c inventoryCursor
	if err = json.Unmarshal(b, &c); err != nil || c.Version != 1 || c.Endpoint == "" || c.Signature != inventoryQuerySignature(q) {
		return nil, fmt.Errorf("inventory cursor does not match query")
	}
	if c.LastSeen != "" {
		if _, err = time.Parse(time.RFC3339Nano, c.LastSeen); err != nil {
			return nil, fmt.Errorf("invalid inventory cursor timestamp")
		}
	}
	return &c, nil
}

// DecodeInventoryCursorForRequest validates a cursor at the HTTP boundary so
// malformed or legacy numeric cursors return a client error rather than a
// storage failure.
func DecodeInventoryCursorForRequest(q Query, raw string) (bool, error) {
	cursor, err := decodeInventoryCursor(q, raw)
	return cursor != nil, err
}
