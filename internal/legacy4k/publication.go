package legacy4k

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrSnapshotPublicationPending reports a snapshot the endpoint durably accepted whose
// calibration has not published yet. It is not a failed upload: re-reading and re-sending
// the inventory would only create another snapshot to calibrate. On the field the three
// minute wait expired on a busy disk, the bridge re-sent every 3m20s instead of every 30m,
// and each retry rebuilt a 37k-row generation that made the next wait expire too.
var ErrSnapshotPublicationPending = errors.New("identity snapshot accepted; publication pending")

func (s Sender) waitSnapshotPublication(parent context.Context, id, campus, domain string) error {
	ctx, cancel := context.WithTimeout(parent, s.publicationWait())
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
			if parent.Err() != nil {
				return parent.Err()
			}
			return ErrSnapshotPublicationPending
		case <-time.After(time.Second):
		}
	}
}

func (s Sender) publicationWait() time.Duration {
	if s.PublicationWait > 0 {
		return s.PublicationWait
	}
	return 3 * time.Minute
}
