package controlplane

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

type sharedDeviceProfileReaderFixture struct {
	store.Reader
	query    store.SharedDeviceProfileQuery
	detailID string
}

func (r *sharedDeviceProfileReaderFixture) GetSharedDeviceProfile(_ context.Context, id string) (store.SharedDeviceProfileDetail, bool, error) {
	r.detailID = id
	return store.SharedDeviceProfileDetail{Profile: store.SharedDeviceProfile{ProfileID: id}, History: []store.SharedDeviceProfileHistory{}}, true, nil
}

func (r *sharedDeviceProfileReaderFixture) ListSharedDeviceProfiles(_ context.Context, query store.SharedDeviceProfileQuery) (store.SharedDeviceProfilePage, error) {
	r.query = query
	return store.SharedDeviceProfilePage{Items: []store.SharedDeviceProfile{}, Page: store.Page{Limit: query.Limit}, CheckedAt: time.Now(), AsOf: time.Now(), FreshnessState: "fresh"}, nil
}

func TestSharedDeviceProfileFiltersReachMaterializedReader(t *testing.T) {
	reader := &sharedDeviceProfileReaderFixture{}
	server := NewServer(Options{ReadOnly: true})
	server.reader = reader
	request := httptest.NewRequest("GET", "/shared-access/devices?role=router&identity_state=supported&current_shared=true&account_conflict=false&limit=25&cursor=50", nil)
	recorder := httptest.NewRecorder()
	server.handleSharedDeviceProfiles(recorder, request, "/shared-access/devices")
	if recorder.Code != 200 {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	if reader.query.Role != "router" || reader.query.IdentityState != "supported" || reader.query.Limit != 25 || reader.query.Cursor != 50 || reader.query.CurrentShared == nil || !*reader.query.CurrentShared || reader.query.AccountConflict == nil || *reader.query.AccountConflict {
		t.Fatalf("filters not forwarded: %+v", reader.query)
	}
}

func TestSharedDeviceProfileRejectsInvalidBooleanFilter(t *testing.T) {
	reader := &sharedDeviceProfileReaderFixture{}
	server := NewServer(Options{ReadOnly: true})
	server.reader = reader
	request := httptest.NewRequest("GET", "/shared-access/devices?current_shared=maybe", nil)
	recorder := httptest.NewRecorder()
	server.handleSharedDeviceProfiles(recorder, request, "/shared-access/devices")
	if recorder.Code != 400 {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
}

func TestSharedDeviceProfileDetailUsesSameReadPermission(t *testing.T) {
	reader := &sharedDeviceProfileReaderFixture{}
	server := NewServer(Options{ReadOnly: true})
	server.reader = reader
	request := httptest.NewRequest("GET", "/shared-access/devices/profile-one", nil)
	recorder := httptest.NewRecorder()
	server.handleSharedDeviceProfiles(recorder, request, "/shared-access/devices/profile-one")
	if recorder.Code != 200 || reader.detailID != "profile-one" {
		t.Fatalf("detail not read from materialized profile: %d %s %+v", recorder.Code, recorder.Body.String(), reader)
	}
	if permission := requiredPermission("GET", "/shared-access/devices/profile-one"); permission != "cases:read" {
		t.Fatalf("detail permission = %q", permission)
	}
}
