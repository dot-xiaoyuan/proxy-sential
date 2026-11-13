package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
)

type passiveBatchEventPosition struct {
	Ordinal  int
	Hash     string
	Document string
}

func passiveDiscoveryBatchV3Enabled() bool {
	return os.Getenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_BATCH_V3_STAGE") == "true"
}

func passiveDiscoveryBatchV3Selected(event normalized.Event) bool {
	switch event.SourceEventType {
	case "dhcp", "arp", "ndp", "ssdp", "ws_discovery", "sadp", "lldp", "cdp", "ieee1905_client_association", "ieee1905_topology", "ttl", "http-device", "snmp", "tls", "ssl", "x509", "sip", "rtsp", "bacnet", "modbus":
		return true
	case "mdns":
		return event.Payload["is_response"] == true
	default:
		return false
	}
}

// Hash the original normalized event, then hash the ordered selected manifest.
// One PostgreSQL row can verify every ClickHouse ordinal without storing a
// second copy of each event body or a permanent per-event receipt.
func passiveDiscoveryBatchV3Manifest(events []normalized.Event) (map[string]passiveBatchEventPosition, int, string, error) {
	positions := make(map[string]passiveBatchEventPosition)
	manifest := sha256.New()
	count := 0
	for _, event := range events {
		if !passiveDiscoveryBatchV3Selected(event) {
			continue
		}
		if event.EventID == "" {
			return nil, 0, "", fmt.Errorf("discovery batch event ID is empty")
		}
		if _, exists := positions[event.EventID]; exists {
			return nil, 0, "", fmt.Errorf("discovery batch event ID is duplicated: %s", event.EventID)
		}
		raw, err := json.Marshal(event)
		if err != nil {
			return nil, 0, "", err
		}
		content := sha256.Sum256(raw)
		hash := hex.EncodeToString(content[:])
		positions[event.EventID] = passiveBatchEventPosition{Ordinal: count, Hash: hash, Document: string(raw)}
		manifest.Write([]byte(strconv.Itoa(count)))
		manifest.Write([]byte{0})
		manifest.Write([]byte(event.EventID))
		manifest.Write([]byte{0})
		manifest.Write([]byte(hash))
		manifest.Write([]byte{0})
		count++
		if count > 20000 {
			return nil, 0, "", fmt.Errorf("discovery batch selection exceeds 20000 events")
		}
	}
	return positions, count, hex.EncodeToString(manifest.Sum(nil)), nil
}

func (s *DBStore) stagePassiveDiscoveryBatchV3(ctx context.Context, batch ingest.Batch, events []normalized.Event) error {
	positions, count, hash, err := passiveDiscoveryBatchV3Manifest(events)
	if err != nil {
		return err
	}
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO passive_discovery_batch_progress(batch_id,selected_count,selection_sha256)
VALUES($1,$2,$3) ON CONFLICT(batch_id) DO NOTHING`, batch.BatchID, count, hash)
	if err != nil {
		return err
	}
	var storedCount int
	var storedHash string
	var started time.Time
	if err = s.pg.db.QueryRowContext(ctx, `SELECT p.selected_count,p.selection_sha256,b.started_at FROM passive_discovery_batch_progress p JOIN ingest_batches b USING(batch_id) WHERE p.batch_id=$1`, batch.BatchID).Scan(&storedCount, &storedHash, &started); err != nil {
		return err
	}
	if storedCount != count || storedHash != hash {
		return fmt.Errorf("passive discovery batch content conflict: %s", batch.BatchID)
	}
	if count == 0 {
		return nil
	}
	var body bytes.Buffer
	body.WriteString("INSERT INTO passive_discovery_events_v3 SETTINGS async_insert=0,date_time_input_format='best_effort' FORMAT JSONEachRow\n")
	encode := json.NewEncoder(&body)
	ingested := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
	for _, event := range events {
		if !passiveDiscoveryBatchV3Selected(event) {
			continue
		}
		position := positions[event.EventID]
		sensor := stringFromMap(event.Observer, "sensor_id")
		if sensor != batch.SensorID {
			return fmt.Errorf("passive discovery v3 event sensor %q differs from batch sensor %q", sensor, batch.SensorID)
		}
		observed, parseErr := time.Parse(time.RFC3339Nano, event.Timestamp)
		if parseErr != nil {
			return parseErr
		}
		row := map[string]any{
			"ingested_at": ingested, "batch_started_at": started.UTC().Format("2006-01-02 15:04:05.000000"),
			"batch_id": batch.BatchID, "ordinal": position.Ordinal, "event_content_sha256": position.Hash,
			"event_json": position.Document, "timestamp": observed.UTC().Format("2006-01-02 15:04:05.000000"),
			"event_id": event.EventID, "sensor_id": sensor, "source_event_type": event.SourceEventType,
		}
		if err = encode.Encode(row); err != nil {
			return err
		}
		if body.Len() > 16<<20 {
			return fmt.Errorf("passive discovery batch v3 exceeds 16 MiB")
		}
	}
	return s.ch.exec(ctx, body.String())
}
