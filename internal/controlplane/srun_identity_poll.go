package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/store"
)

func (s *Server) readSRunIdentitySnapshot(ctx context.Context, item srun4KIntegration) (store.IdentitySnapshot, legacy4k.InventoryStats, error) {
	var empty store.IdentitySnapshot
	defaults := s.srun4KDefaults.normalized()
	client := s.srunRedis(item)
	defer client.Close()
	inventory, err := legacy4k.ReadOnlineInventoryPaged(ctx, client, "list:rad_online", defaults.MaxSessions, defaults.PageSize)
	if err != nil {
		return empty, legacy4k.InventoryStats{}, fmt.Errorf("读取4K完整在线清单失败: %w", err)
	}
	records, stats, err := inventory.IdentityRecordsWithStatsContext(ctx)
	if err != nil {
		return empty, stats, identityLocalWorkError(err)
	}
	count := len(records)
	request := identitySnapshotRequest{IdentityScope: store.IdentityScope{Source: item.Source, SensorID: item.SensorID}, ObservedAt: inventory.ObservedAt, IntervalSeconds: item.ReconcileIntervalHours * 3600, Complete: true, ExpectedCount: &count, Records: records}
	id, err := srunIdentitySnapshotIDContext(ctx, request)
	if err != nil {
		return empty, stats, identityLocalWorkError(err)
	}
	snapshot, err := prepareIdentitySnapshotContext(ctx, request, id, time.Now().UTC(), legacy4k.MaxIdentityAddressRecords)
	return snapshot, stats, identityLocalWorkError(err)
}

// Compare standardized membership, including login generation and source
// instance. Receipt times, event IDs and raw references are not membership.
// Per-member hashes bound extra memory and make Redis list order irrelevant.
func sameSRunIdentityMembers(ctx context.Context, left, right store.IdentitySnapshot) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if left.IdentityScope != right.IdentityScope || left.IntervalSeconds != right.IntervalSeconds || len(left.Events) != len(right.Events) {
		return false, nil
	}
	hashes := func(snapshot store.IdentitySnapshot) ([]string, error) {
		out := make([]string, 0, len(snapshot.Events))
		for _, event := range snapshot.Events {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			event.Timestamp, event.EventID, event.RawRef = "", "", nil
			raw, err := json.Marshal(event)
			if err != nil {
				return nil, err
			}
			digest := sha256.Sum256(raw)
			out = append(out, string(digest[:]))
		}
		sort.Strings(out)
		return out, ctx.Err()
	}
	lh, err := hashes(left)
	if err != nil {
		return false, err
	}
	rh, err := hashes(right)
	if err != nil {
		return false, err
	}
	for i := range lh {
		if lh[i] != rh[i] {
			return false, nil
		}
	}
	return true, ctx.Err()
}

// While accounting events are unavailable, poll once per scheduler minute.
// Save a full standard snapshot only when membership changes; the existing
// full calibration refreshes unchanged inventories. This keeps historical
// replay volume bounded and never certifies the event channel or enables actions.
func (s *Server) pollSRunIdentity(ctx context.Context, id string) (err error) {
	item, err := s.loadSRun4K(ctx, id)
	if err != nil || (item.EventChannelState == "healthy" && item.LastIdentityEventAt != nil && time.Since(*item.LastIdentityEventAt) < 2*time.Minute) {
		return err
	}
	ctx, err = s.beginSRunOperation(ctx, item)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			s.recordSRunOperationFailure(ctx, id, err.Error(), "integration.srun4k.identity_poll")
		}
	}()
	snapshot, _, err := s.readSRunIdentitySnapshot(ctx, item)
	if err != nil {
		return err
	}
	return s.commitSRunIdentityPoll(ctx, item, snapshot)
}

func (s *Server) commitSRunIdentityPoll(ctx context.Context, item srun4KIntegration, snapshot store.IdentitySnapshot) (err error) {
	id := item.ConnectorID
	if _, err = s.operations.db.ExecContext(ctx, `UPDATE srun4k_integrations SET last_identity_poll_at=now(),event_channel_state=CASE WHEN last_identity_event_at IS NOT NULL AND last_identity_event_at>now()-interval '2 minutes' THEN event_channel_state ELSE 'waiting' END WHERE connector_id=$1 AND host=$2 AND source=$3 AND sensor_id=$4 AND reconcile_interval_hours=$5`, id, item.Host, item.Source, item.SensorID, item.ReconcileIntervalHours); err != nil {
		return err
	}
	var raw []byte
	err = s.operations.db.QueryRowContext(ctx, `SELECT document FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id='' AND access_domain='' ORDER BY observed_at DESC LIMIT 1`, item.Source, item.SensorID).Scan(&raw)
	if err == nil {
		var previous store.IdentitySnapshot
		if err = json.Unmarshal(raw, &previous); err != nil {
			return err
		}
		var same bool
		if same, err = sameSRunIdentityMembers(ctx, previous, snapshot); err != nil || same {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// A poll begun before an address/configuration change cannot publish itself
	// as the new gateway's identity source.
	var current bool
	if err = s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM srun4k_integrations WHERE connector_id=$1 AND host=$2 AND source=$3 AND sensor_id=$4 AND reconcile_interval_hours=$5)`, id, item.Host, item.Source, item.SensorID, item.ReconcileIntervalHours).Scan(&current); err != nil {
		return err
	}
	if !current {
		return nil
	}
	reconciler, ok := s.reader.(store.IdentityReconciler)
	if !ok {
		return fmt.Errorf("身份快照存储不可用")
	}
	_, err = reconciler.CommitIdentitySnapshot(ctx, snapshot)
	return err
}
