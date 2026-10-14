package controlplane

import (
	"context"
	"database/sql"
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
	// Only scalar columns: the inventory document is deliberately never read here,
	// so sqlmock fails the test if such a query reappears.
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT observed_at,session_count FROM identity_full_snapshots WHERE source=$1 ORDER BY observed_at DESC,received_at DESC LIMIT 1`)).
		WithArgs("ncu-srun4k").
		WillReturnRows(sqlmock.NewRows([]string{"observed_at", "session_count"}).AddRow(time.Now().UTC(), 1))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT group_id,name,parent_id,path FROM srun4k_group_catalog WHERE active AND source IN ($1,$2,$3) ORDER BY group_id`)).
		WithArgs(identityGroupCatalogSource("ncu-srun4k"), managedGroupCatalogSource("ncu-srun4k", 4), "ncu-srun4k").
		WillReturnRows(sqlmock.NewRows([]string{"group_id", "name", "parent_id", "path"}).
			AddRow("12", "", "", "").
			AddRow("12", "真实用户组", "1", "/信息工程学院").
			AddRow("99", "未上线用户组", "1", "/信息工程学院"))
	directory, err := loadFourKDirectoryWithGroupSource(context.Background(), db, "ncu-srun4k", "", managedGroupCatalogSource("ncu-srun4k", 4))
	if err != nil || len(directory.Groups) != 2 || directory.Groups[0].Name != "未上线用户组" || directory.Groups[1].Name != "真实用户组" {
		t.Fatalf("directory=%+v err=%v", directory, err)
	}
	// The tree must survive the merge with the id-only observation: losing the
	// parent would flatten a real organisational hierarchy in the selector.
	for _, group := range directory.Groups {
		if group.ParentID != "1" || group.Path != "/信息工程学院" {
			t.Fatalf("group tree lost in merge: %+v", group)
		}
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// An id-only entry observed online must never blank the name the northbound
// catalog published for the same group.
func TestGroupDirectoryPrefersNamedEntries(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT product_id,name FROM product_catalog`).
		WithArgs("ncu-srun4k", "").
		WillReturnRows(sqlmock.NewRows([]string{"product_id", "name"}))
	mock.ExpectQuery(`SELECT observed_at,\(SELECT count\(\*\) FROM product_control_catalog`).
		WithArgs("ncu-srun4k", "").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT observed_at,session_count FROM identity_full_snapshots`)).
		WithArgs("ncu-srun4k").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT group_id,name,parent_id,path FROM srun4k_group_catalog WHERE active AND source IN ($1,$2,$3) ORDER BY group_id`)).
		WithArgs(identityGroupCatalogSource("ncu-srun4k"), "ncu-srun4k", "ncu-srun4k").
		WillReturnRows(sqlmock.NewRows([]string{"group_id", "name", "parent_id", "path"}).
			AddRow("12", "真实用户组", "1", "/信息工程学院").
			AddRow("12", "", "", ""))
	directory, err := loadFourKDirectoryWithGroupSource(context.Background(), db, "ncu-srun4k", "", "ncu-srun4k")
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Groups) != 1 || directory.Groups[0].Name != "真实用户组" {
		t.Fatalf("named entry lost: %+v", directory.Groups)
	}
	// No identity snapshot row is not an error: the group directory still loads.
	if directory.IdentityObservedAt != nil || directory.IdentitySessions != 0 {
		t.Fatalf("unexpected identity state: %+v", directory)
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
