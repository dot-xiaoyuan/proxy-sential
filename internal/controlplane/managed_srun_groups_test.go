package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/srunapi"
)

func TestManagedGroupCatalogSourceIsolatedByBridgeVersion(t *testing.T) {
	if got := managedGroupCatalogSource("ncu-srun4k", 7); got != "ncu-srun4k:bridge-v7" {
		t.Fatalf("source=%q", got)
	}
	for _, tc := range []struct {
		source  string
		version int64
	}{{"", 1}, {"ncu-srun4k", 0}, {"ncu-srun4k", -1}} {
		if got := managedGroupCatalogSource(tc.source, tc.version); got != "" {
			t.Fatalf("invalid scope produced source %q", got)
		}
	}
}

func TestManagedFourKDirectoryJoinsNamesFromCurrentGroupVersion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT product_id,name FROM product_catalog`).WithArgs("ncu-srun4k", "").WillReturnRows(sqlmock.NewRows([]string{"product_id", "name"}))
	mock.ExpectQuery(`SELECT observed_at,\(SELECT count\(\*\) FROM product_control_catalog`).WithArgs("ncu-srun4k", "").WillReturnError(sql.ErrNoRows)
	identity, err := json.Marshal(map[string]any{"events": []map[string]any{{"subject": map[string]any{"account_id": "acct"}, "payload": map[string]any{"group_id": "12"}}}})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`SELECT document,observed_at,session_count FROM identity_full_snapshots`).WithArgs("ncu-srun4k").WillReturnRows(sqlmock.NewRows([]string{"document", "observed_at", "session_count"}).AddRow(identity, time.Now().UTC(), 1))
	mock.ExpectQuery(`SELECT group_id,name FROM srun4k_group_catalog WHERE source=\$1 AND active`).WithArgs("ncu-srun4k:bridge-v4").WillReturnRows(sqlmock.NewRows([]string{"group_id", "name"}).AddRow("12", "真实用户组").AddRow("99", "未上线用户组"))
	directory, err := loadFourKDirectoryWithGroupSource(context.Background(), db, "ncu-srun4k", "", managedGroupCatalogSource("ncu-srun4k", 4))
	if err != nil || len(directory.Groups) != 2 || directory.Groups[0].Name != "未上线用户组" || directory.Groups[1].Name != "真实用户组" {
		t.Fatalf("directory=%+v err=%v", directory, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedGroupSyncTargetRequiresRecentCommittedIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT active_host,active_config_version FROM identity_bridge_runtime WHERE bridge_id=$1 AND active_config_version>0 AND last_snapshot_at>now()-interval '30 seconds'`)).
		WithArgs(ncuIdentityBridgeID).
		WillReturnRows(sqlmock.NewRows([]string{"active_host", "active_config_version"}).AddRow("222.204.3.224", 4))
	target, err := managedSRunGroupTargetFor(context.Background(), db, ncuIdentityBridgeID)
	if err != nil || target != (managedSRunGroupTarget{host: "222.204.3.224", version: 4}) {
		t.Fatalf("target=%+v err=%v", target, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedGroupCommitRejectsStaleBridgeAddress(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT active_host,active_config_version FROM identity_bridge_runtime WHERE bridge_id=\$1 FOR SHARE`).
		WithArgs(ncuIdentityBridgeID).
		WillReturnRows(sqlmock.NewRows([]string{"active_host", "active_config_version"}).AddRow("222.204.3.225", 5))
	mock.ExpectRollback()
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	err = s.commitSRunGroupsScoped(context.Background(), managedGroupCatalogSource("ncu-srun4k", 4), []srunapi.Group{{ID: "12", Name: "学生组"}}, observedAt, "222.204.3.224", 4)
	if !errors.Is(err, errBridgeCatalogScope) {
		t.Fatalf("stale group directory accepted: %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedGroupErrorCategoryDoesNotExposeSourceDetails(t *testing.T) {
	for _, tc := range []struct {
		input error
		want  string
	}{{context.DeadlineExceeded, "context deadline exceeded"}, {errors.New("secret mysql password"), "northbound_unavailable"}} {
		got := managedGroupReadErrorType(tc.input).Error()
		if got != tc.want {
			t.Fatalf("category=%q want=%q", got, tc.want)
		}
	}
}
