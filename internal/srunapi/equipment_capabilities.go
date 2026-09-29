package srunapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// This inspects the actual unfiltered endpoint shape without manufacturing an
// authoritative snapshot. It exposes field names only, never account inventory.
type EquipmentCapabilities struct {
	Shape       string   `json:"shape"`
	RecordCount int      `json:"record_count"`
	Fields      []string `json:"fields"`
	Complete    bool     `json:"complete"`
	Blocker     string   `json:"blocker"`
}

func (c *Client) InspectEquipmentCapabilities(ctx context.Context) (EquipmentCapabilities, error) {
	return c.inspectInventoryShape(ctx, "/api/v2/base/online-equipment")
}

func (c *Client) InspectOnlineDataCapabilities(ctx context.Context) (EquipmentCapabilities, error) {
	return c.inspectInventoryShape(ctx, "/api/v2/base/online-data")
}

func (c *Client) inspectInventoryShape(ctx context.Context, endpoint string) (EquipmentCapabilities, error) {
	result := EquipmentCapabilities{Complete: false, Blocker: "inventory_completeness_unproven", Fields: []string{}}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	token, err := c.authenticate(ctx)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrAuthentication, err)
	}
	method := http.MethodPost
	if endpoint == "/api/v2/base/online-data" {
		method = http.MethodGet
	}
	data, err := c.requestBounded(ctx, method, endpoint, url.Values{"access_token": {token}}, 16<<20)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrReadOnlyQuery, err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return result, fmt.Errorf("%w: missing equipment data", ErrReadOnlyQuery)
	}
	var fields map[string]bool = map[string]bool{}
	switch data[0] {
	case '[':
		result.Shape = "array"
		var rows []map[string]json.RawMessage
		if json.Unmarshal(data, &rows) != nil || len(rows) > 10000 {
			return result, fmt.Errorf("%w: invalid or oversized inventory", ErrReadOnlyQuery)
		}
		result.RecordCount = len(rows)
		for _, row := range rows {
			for key := range row {
				fields[key] = true
			}
		}
	case '{':
		result.Shape = "object"
		var obj map[string]json.RawMessage
		if json.Unmarshal(data, &obj) != nil {
			return result, fmt.Errorf("%w: invalid equipment contract", ErrReadOnlyQuery)
		}
		for key := range obj {
			fields[key] = true
		}
	default:
		result.Shape = "scalar"
		result.Blocker = "unfiltered_equipment_inventory_unsupported"
	}
	for key := range fields {
		result.Fields = append(result.Fields, key)
	}
	sort.Strings(result.Fields)
	return result, nil
}
