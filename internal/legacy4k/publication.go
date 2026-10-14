package legacy4k

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s Sender) waitSnapshotPublication(ctx context.Context, id, campus, domain string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	source := s.Source
	if source == "" {
		source = "legacy-4k"
	}
	query := url.Values{"source": {source}, "sensor_id": {s.SensorID}, "campus_id": {campus}, "access_domain": {domain}, "snapshot_id": {id}}
	endpoint := strings.TrimRight(s.Endpoint, "/") + "/api/v1/integrations/identity/snapshot-publication?" + query.Encode()
	for {
		var receipt struct {
			ID        string `json:"snapshot_id"`
			Published bool   `json:"published"`
			State     string `json:"calibration_state"`
		}
		err := s.snapshotJSONRequest(ctx, http.MethodGet, endpoint, nil, "", &receipt)
		if err == nil && receipt.ID == id && receipt.Published {
			return nil
		}
		if err == nil && receipt.State == "failed" {
			return fmt.Errorf("identity snapshot calibration failed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
