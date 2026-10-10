package productpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Sender struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

const BridgeCatalogPath = "/api/v1/integrations/identity/bridge/catalog-snapshots"

type BridgeCatalogSnapshot struct {
	Host          string   `json:"host"`
	ConfigVersion int64    `json:"config_version"`
	Snapshot      Snapshot `json:"snapshot"`
}

func (s BridgeCatalogSnapshot) ID() string {
	return fmt.Sprintf("bridge-catalog-v%d-%s", s.ConfigVersion, s.Snapshot.ContentHash)
}

func (s Sender) Send(ctx context.Context, snapshot Snapshot, snapshotID string) error {
	return s.send(ctx, snapshot, snapshot.ContentHash, snapshotID, "/api/v1/integrations/product-policy/snapshots")
}

// This narrowly scoped channel shares the identity bridge's credential, not
// the generic product-import credential or any enforcement connector.
func (s Sender) SendBridgeCatalog(ctx context.Context, value BridgeCatalogSnapshot, snapshotID string) error {
	return s.send(ctx, value, value.Snapshot.ContentHash, snapshotID, BridgeCatalogPath)
}

func (s Sender) send(ctx context.Context, value any, contentHash, snapshotID, path string) error {
	if strings.TrimSpace(s.Endpoint) == "" || strings.TrimSpace(s.Token) == "" || strings.TrimSpace(snapshotID) == "" {
		return fmt.Errorf("endpoint, token and snapshot ID required")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.Endpoint, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", snapshotID)
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusOK {
		return fmt.Errorf("product-policy snapshot endpoint returned %s", response.Status)
	}
	var ack struct {
		SnapshotID  string `json:"snapshot_id"`
		Status      string `json:"status"`
		ContentHash string `json:"content_hash"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&ack); err != nil || ack.Status != "completed" || ack.ContentHash != contentHash {
		return fmt.Errorf("product-policy snapshot acknowledgement mismatch")
	}
	return nil
}
