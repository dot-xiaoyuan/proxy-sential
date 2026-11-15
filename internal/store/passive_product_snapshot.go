package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"proxy-sentinel/internal/discovery"
)

// SnapshotProductResponses reads only an explicit frozen set of retained
// observation primary keys. It never scans historical network traffic.
func SnapshotProductResponses(ctx context.Context, db HardwareRepairTxStarter, w HardwareRepairWindow, ids []string) (HardwareRepairManifest, error) {
	m := HardwareRepairManifest{SchemaVersion: HardwareRepairSchema, Window: w, Entries: []HardwareRepairEntry{}}
	if err := w.validate(); err != nil {
		return m, err
	}
	if w.Origin != "snmp" || len(ids) == 0 || len(ids) > 1000 {
		return m, fmt.Errorf("product snapshot requires SNMP and 1..1000 explicit observation IDs")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || len(id) > 256 || seen[id] {
			return m, fmt.Errorf("invalid or duplicate observation ID")
		}
		seen[id] = true
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return m, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, `SELECT now()`).Scan(&m.SnapshotAt); err != nil {
		return m, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,device_key,source_id,origin,observed_at,data::text FROM discovery_observations WHERE id=ANY($1::text[]) ORDER BY id`, ids)
	if err != nil {
		return m, err
	}
	total := 0
	for rows.Next() {
		var id, key, source, origin string
		var at time.Time
		var raw []byte
		if err = rows.Scan(&id, &key, &source, &origin, &at, &raw); err != nil {
			rows.Close()
			return m, err
		}
		total += len(raw)
		if len(raw) > HardwareRepairMaxRowBytes || total > HardwareRepairMaxSnapshotBytes {
			rows.Close()
			return m, fmt.Errorf("product snapshot exceeds byte bounds")
		}
		var o discovery.Observation
		if err = json.Unmarshal(raw, &o); err != nil {
			rows.Close()
			return m, err
		}
		if o.ID != id || o.Key() != key || o.SourceID != source || o.Origin != origin || o.Node != w.Sensor || origin != "snmp" || !o.ObservedAt.Truncate(time.Microsecond).Equal(at) {
			rows.Close()
			return m, fmt.Errorf("product source columns disagree with observation")
		}
		e := makeHardwareRepairEntry([5]string{key, source, origin, discovery.SNMPProductPartition(o), o.Port}, raw, o)
		e.SourceRelation = "observation"
		m.Entries = append(m.Entries, e)
		delete(seen, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return m, err
	}
	if len(seen) > 0 {
		missing := make([]string, 0, len(seen))
		for id := range seen {
			missing = append(missing, id)
		}
		sort.Strings(missing)
		return m, fmt.Errorf("source observations not retained: %v", missing)
	}
	if err = m.Validate(); err != nil {
		return m, err
	}
	if err = tx.Commit(); err != nil {
		return m, err
	}
	return m, nil
}
