package discovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/pagination"
)

func TestDiscoveryHistoryMetadataPositionAndReadShareDeviceEpochAndSnapshot(t *testing.T) {
	for _, epoch := range []string{"", "fresh-history"} {
		t.Run("epoch="+epoch, func(t *testing.T) {
			db, mock, _ := sqlmock.New()
			defer db.Close()
			repo := Repository{DB: db}
			ctx := context.Background()
			stamp := time.Now().UTC()
			expectEpoch := func() {
				rows := sqlmock.NewRows([]string{"epoch"})
				if epoch != "" {
					rows.AddRow(epoch)
				}
				mock.ExpectQuery("SELECT s.epoch FROM stream_discovery_device_state s").WithArgs("device-a").WillReturnRows(rows)
			}
			expectEpoch()
			if epoch == "" {
				mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM discovery_device_changes_v2`).WithArgs("device-a").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectQuery(`SELECT count\(\*\) FROM discovery_device_changes_v2 WHERE device_key=\$1 AND ingested_at<=\$2`).WithArgs("device-a", stamp).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
			} else {
				mock.ExpectQuery(`SELECT count\(\*\) FROM stream_discovery_changes WHERE epoch=\$1 AND device_key=\$2 AND accepted_at<=\$3`).WithArgs(epoch, "device-a", stamp).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
			}
			metadata, err := repo.DiscoveryHistoryMetadata(ctx, "device-a", stamp)
			if err != nil || metadata.Total != 4 || !metadata.Snapshot.Equal(stamp) {
				t.Fatal(metadata, err)
			}
			expectEpoch()
			rows := sqlmock.NewRows([]string{"change_id"}).AddRow(30).AddRow(20)
			if epoch == "" {
				mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM discovery_device_changes_v2`).WithArgs("device-a").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectQuery(`SELECT change_id FROM discovery_device_changes_v2.*ORDER BY change_id DESC LIMIT 2 OFFSET \$3`).WithArgs("device-a", stamp, int64(1)).WillReturnRows(rows)
			} else {
				mock.ExpectQuery(`SELECT change_id FROM stream_discovery_changes.*ORDER BY change_id DESC LIMIT 2 OFFSET \$4`).WithArgs(epoch, "device-a", stamp, int64(1)).WillReturnRows(rows)
			}
			pos, err := repo.DiscoveryHistoryPosition(ctx, "device-a", stamp, 2, 2)
			if err != nil || pos.Page != 2 || pos.Limit != 2 || !pos.Snapshot.Equal(stamp) {
				t.Fatal(pos, err)
			}
			var cursor streamHistoryCursor
			raw, _ := base64.RawURLEncoding.DecodeString(pos.Cursor)
			_ = json.Unmarshal(raw, &cursor)
			if cursor.Key != "device-a" || cursor.Epoch != epoch || cursor.After != 30 || (epoch == "" && cursor.Version != 2) || (epoch != "" && cursor.Version != 3) {
				t.Fatal("bad bound cursor", string(raw))
			}
			expectEpoch()
			if epoch == "" {
				mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM discovery_device_changes_v2`).WithArgs("device-a").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectQuery(`SELECT change_id,event_id,ingested_at,observed_at,change_kind,document.*ingested_at<=\$4`).WithArgs("device-a", int64(30), 3, stamp).WillReturnRows(sqlmock.NewRows([]string{"change_id", "event_id", "ingested_at", "observed_at", "kind", "document"}).AddRow(20, "event-20", stamp, stamp, "applied", []byte(`{}`)))
			} else {
				mock.ExpectQuery(`(?s)SELECT c.change_id.*FROM stream_discovery_changes c.*accepted_at<=\$5`).WithArgs(epoch, "device-a", int64(30), 3, stamp).WillReturnRows(sqlmock.NewRows([]string{"change_id", "event_key", "accepted_at", "observed_at", "kind", "before", "after", "body_ref", "archive_state", "legacy_present"}).AddRow(20, "event-20", stamp, stamp, "applied", "", "hash", []byte(`{}`), "confirmed", true))
			}
			page, err := repo.DiscoveryHistoryAt(ctx, "device-a", pos.Cursor, 2, stamp)
			if err != nil || len(page["items"].([]map[string]any)) != 1 {
				t.Fatal(page, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDiscoveryHistoryPositionRejectsMissingTargetAndInvalidBounds(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	repo := Repository{DB: db}
	ctx := context.Background()
	stamp := time.Now().UTC()
	for _, p := range []struct{ page, limit int }{{0, 20}, {2, 101}, {-1, 20}} {
		if _, err := repo.DiscoveryHistoryPosition(ctx, "a", stamp, p.page, p.limit); err == nil {
			t.Fatal("invalid bounds accepted", p)
		}
	}
	if _, err := repo.DiscoveryHistoryMetadata(ctx, "", stamp); err == nil {
		t.Fatal("empty device accepted")
	}
	// Page one remains available when the matching index is empty.
	first, err := repo.DiscoveryHistoryPosition(ctx, "a", stamp, 1, 20)
	if err != nil || first.Cursor != "" {
		t.Fatal(first, err)
	}
	mock.ExpectQuery("SELECT s.epoch FROM stream_discovery_device_state s").WithArgs("a").WillReturnRows(sqlmock.NewRows([]string{"epoch"}))
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM discovery_device_changes_v2`).WithArgs("a").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery(`SELECT change_id FROM discovery_device_changes_v2.*LIMIT 2 OFFSET`).WithArgs("a", stamp, int64(1)).WillReturnRows(sqlmock.NewRows([]string{"change_id"}).AddRow(1))
	if _, err := repo.DiscoveryHistoryPosition(ctx, "a", stamp, 2, 2); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatal("last full page incorrectly exposed another page", err)
	}
	// The returned cursor may never be reused for a different device.
	raw, _ := json.Marshal(streamHistoryCursor{Key: "other", After: 30, Version: 2})
	mock.ExpectQuery("SELECT s.epoch FROM stream_discovery_device_state s").WithArgs("a").WillReturnRows(sqlmock.NewRows([]string{"epoch"}))
	if _, err := repo.DiscoveryHistoryAt(ctx, "a", base64.RawURLEncoding.EncodeToString(raw), 2, stamp); err == nil {
		t.Fatal("cross-device cursor accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
