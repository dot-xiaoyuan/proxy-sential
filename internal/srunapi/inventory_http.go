package srunapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxy-sentinel/internal/legacy4k"
)

// InventoryDocument is the complete authority contract of an existing online
// inventory API/bridge. A total-only response or partial page is never absence.
type InventoryDocument struct {
	SchemaVersion string              `json:"schema_version"`
	InstanceID    string              `json:"instance_id"`
	ObservedAt    time.Time           `json:"observed_at"`
	CampusID      string              `json:"campus_id"`
	AccessDomain  string              `json:"access_domain"`
	Complete      bool                `json:"complete"`
	ExpectedCount *int                `json:"expected_count"`
	Rows          []map[string]string `json:"rows"`
}

type InventoryHTTP struct {
	URL, Token, CampusID, AccessDomain string
	MaxRecords                         int
	Client                             *http.Client
	Now                                func() time.Time
}

func NewInventoryHTTP(endpoint, token, campus, domain string, limit int, client *http.Client) (*InventoryHTTP, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || token == "" || campus == "" || domain == "" || limit < 1 || limit > 10000 {
		return nil, fmt.Errorf("inventory HTTPS endpoint, bearer credential, scope and bound required")
	}
	hc := http.Client{Timeout: 3 * time.Second}
	if client != nil {
		hc = *client
		hc.Timeout = 3 * time.Second
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &InventoryHTTP{URL: endpoint, Token: token, CampusID: campus, AccessDomain: domain, MaxRecords: limit, Client: &hc, Now: time.Now}, nil
}

func (r *InventoryHTTP) Read(ctx context.Context) (legacy4k.OnlineInventory, error) {
	var empty legacy4k.OnlineInventory
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return empty, fmt.Errorf("inventory request construction failed")
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	res, err := r.Client.Do(req)
	if err != nil {
		return empty, fmt.Errorf("inventory transport unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("inventory API HTTP status %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 16<<20+1))
	if err != nil || len(data) > 16<<20 {
		return empty, fmt.Errorf("inventory response incomplete or oversized")
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	var doc InventoryDocument
	if d.Decode(&doc) != nil {
		return empty, fmt.Errorf("invalid inventory contract")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || doc.SchemaVersion != "online-inventory/v1" || !doc.Complete || doc.Rows == nil || doc.ExpectedCount == nil || *doc.ExpectedCount != len(doc.Rows) || len(doc.Rows) > r.MaxRecords || doc.CampusID != r.CampusID || doc.AccessDomain != r.AccessDomain {
		return empty, fmt.Errorf("inventory completeness, count or scope invalid")
	}
	now := r.Now().UTC()
	if doc.ObservedAt.IsZero() || doc.ObservedAt.After(now) || now.Sub(doc.ObservedAt) > 5*time.Second || doc.ObservedAt.Nanosecond()%1000 != 0 {
		return empty, fmt.Errorf("inventory source time invalid or older than five seconds")
	}
	seen := map[string]bool{}
	for _, row := range doc.Rows {
		id := row["rad_online_id"]
		if id == "" || strings.TrimSpace(id) != id || seen[id] || row["session_id"] == "" || row["user_name"] == "" || row["add_time"] == "" {
			return empty, fmt.Errorf("inventory session, account, native ID or login generation missing")
		}
		seen[id] = true
	}
	in := legacy4k.OnlineInventory{InstanceID: doc.InstanceID, ObservedAt: doc.ObservedAt, Rows: doc.Rows}
	if _, err := in.IdentityRecords(); err != nil {
		return empty, fmt.Errorf("invalid inventory identities")
	}
	return in, nil
}
