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

func (s Sender) Send(ctx context.Context, snapshot Snapshot, snapshotID string) error {
	if strings.TrimSpace(s.Endpoint) == "" || strings.TrimSpace(s.Token) == "" || strings.TrimSpace(snapshotID) == "" {
		return fmt.Errorf("endpoint, token and snapshot ID required")
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.Endpoint, "/")+"/api/v1/integrations/product-policy/snapshots", bytes.NewReader(body))
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
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&ack); err != nil || ack.Status != "completed" || ack.ContentHash != snapshot.ContentHash {
		return fmt.Errorf("product-policy snapshot acknowledgement mismatch")
	}
	return nil
}
