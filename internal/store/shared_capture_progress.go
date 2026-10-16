package store

import (
	"context"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
)

// Coverage heartbeats describe actual capture, independently of whether any IP
// contributed a candidate. An idle capture must not look like a stopped process.
func (s *DBStore) recordSharedCaptureProgress(ctx context.Context, events []normalized.Event) error {
	for _, event := range events {
		if event.SourceEventType != "capture_coverage" || (event.Source != "handshake-sidecar" && event.Source != "packet-sidecar") {
			continue
		}
		raw, err := json.Marshal(event.Payload["capture_coverage"])
		if err != nil {
			return err
		}
		var c sharedaccess.CoverageV2
		if err = json.Unmarshal(raw, &c); err != nil {
			return err
		}
		if c.SchemaVersion != "capture-coverage/v2" || c.From.IsZero() || !c.To.After(c.From) {
			continue
		}
		sensor, campus, domain, instance := stringFromMap(event.Observer, "sensor_id"), stringFromMap(event.Subject, "campus_id"), stringFromMap(event.Payload, "access_domain"), stringFromMap(event.Observer, "collector_instance_id")
		if campus == "" {
			campus = stringFromMap(event.Payload, "campus_id")
		}
		if sensor == "" || instance == "" {
			continue
		}
		_, err = s.pg.db.ExecContext(ctx, `INSERT INTO shared_capture_progress(sensor_id,campus_id,access_domain,source,collector_instance_id,covered_from,covered_to,complete,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
 ON CONFLICT(sensor_id,campus_id,access_domain,source,collector_instance_id) DO UPDATE SET covered_from=EXCLUDED.covered_from,covered_to=EXCLUDED.covered_to,complete=EXCLUDED.complete,document=EXCLUDED.document,received_at=now() WHERE EXCLUDED.covered_to>=shared_capture_progress.covered_to`, sensor, campus, domain, event.Source, instance, c.From, c.To, c.Complete(), raw)
		if err != nil {
			return err
		}
	}
	return nil
}
