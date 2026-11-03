package discovery

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

type currentSourceMatcher struct{ query *string }

func (m currentSourceMatcher) Match(expected, actual string) error {
	if expected != "current-page" {
		return sqlmock.QueryMatcherRegexp.Match(expected, actual)
	}
	*m.query = actual
	for _, forbidden := range []string{"discovery_device_current_shadow", "discovery_service_facts_shadow", "jsonb_object_agg"} {
		if strings.Contains(actual, forbidden) {
			return fmt.Errorf("retired dependency %s", forbidden)
		}
	}
	for _, required := range []string{"f.document||", "newer.result_version>s.result_version", "s.document->>'current'='true'", "f.scope_id=s.scope_id", "f.valid_until>now()", "s.document->'capabilities'", "WHERE false"} {
		if !strings.Contains(actual, required) {
			return fmt.Errorf("missing current boundary %s", required)
		}
	}
	return nil
}
func TestStreamCurrentReadsAuthorityWithoutShadowOrLegacyFallback(t *testing.T) {
	var query string
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(currentSourceMatcher{&query}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("current-page").WillReturnRows(sqlmock.NewRows([]string{"device_key", "last_seen", "result_version", "document"}).
		AddRow("a", now, 5, []byte(`{"id":"a","name":"printer","current":true,"sensor_id":"s","addresses":["10.0.0.1"]}`)).
		AddRow("b", now.Add(-time.Second), 4, []byte(`{"id":"b","current":true}`)))
	mock.ExpectQuery("FROM \\(SELECT DISTINCT epoch FROM stream_source_cutovers").WillReturnRows(sqlmock.NewRows([]string{"updated", "version"}).AddRow(now, int64(5)))
	mock.ExpectQuery("SELECT count\\(\\*\\)").WillReturnRows(sqlmock.NewRows([]string{"total"}).AddRow(2))
	q := DeviceQuery{Limit: 1, Protocol: "arp", Capability: "printing"}
	page, err := (Repository{DB: db, ActiveStreamOnly: true}).DevicesState(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]map[string]any)
	if len(items) != 1 || items[0]["name"] != "printer" || items[0]["observations"] == nil || page["has_more"] != true {
		t.Fatalf("document/paging lost: %+v", page)
	}
	q.Cursor = page["next_cursor"].(string)
	mock.ExpectQuery("current-page").WillReturnRows(sqlmock.NewRows([]string{"device_key", "last_seen", "result_version", "document"}))
	mock.ExpectQuery("FROM \\(SELECT DISTINCT epoch FROM stream_source_cutovers").WillReturnRows(sqlmock.NewRows([]string{"updated", "version"}).AddRow(now, int64(5)))
	mock.ExpectQuery("SELECT count\\(\\*\\)").WillReturnRows(sqlmock.NewRows([]string{"total"}).AddRow(2))
	if _, err = (Repository{DB: db, ActiveStreamOnly: true}).DevicesState(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`s.last_seen<\$[0-9]+`).MatchString(query) {
		t.Fatal("cursor predicate missing")
	}
	if _, err = (Repository{DB: db}).DevicesState(context.Background(), q); err == nil {
		t.Fatal("current cursor accepted on legacy reader")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
