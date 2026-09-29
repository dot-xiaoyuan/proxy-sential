package srunapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/legacy4k"
	"sync/atomic"
	"testing"
	"time"
)

type testJournal struct {
	claimed   bool
	at        time.Time
	recordErr error
	records   int
	cancelled bool
}

func (j *testJournal) Cancelled(context.Context, DispatchIntent) (bool, error) {
	return j.cancelled, nil
}

func (j *testJournal) Lookup(context.Context, DispatchIntent) (Reservation, bool, error) {
	return Reservation{ReservedAt: j.at}, j.claimed, nil
}

func (j *testJournal) Record(context.Context, DispatchIntent, StepResult, bool) error {
	j.records++
	return j.recordErr
}

func (j *testJournal) Reserve(context.Context, DispatchIntent) (Reservation, error) {
	first := !j.claimed
	j.claimed = true
	return Reservation{SendAllowed: first, ReservedAt: j.at}, nil
}

type testNative struct {
	calls int
	err   error
}

func (n *testNative) RequestDisconnect(context.Context, string, string, string) error {
	n.calls++
	return n.err
}

func (n *testNative) RequestDisconnectChecked(ctx context.Context, a, b, c string, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return ErrDispatchPrevented
	}
	return n.RequestDisconnect(ctx, a, b, c)
}

func TestExecutionTimeoutReconcilesWithoutResend(t *testing.T) {
	now := time.Now().UTC()
	ctx := context.Background()
	in := inventory(now)
	target, _ := BindDisconnect(in, "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
	intent := DispatchIntent{Key: "one", ConnectorID: "test", Target: target, DropType: "radius"}
	j := &testJournal{at: now}
	native := &testNative{err: errors.New("response lost")}
	executor := Executor{Journal: j, Native: native, Now: func() time.Time { return now }, MaxAge: time.Minute, Read: func(context.Context) (legacy4k.OnlineInventory, error) { return in, nil }, Authorize: func(context.Context, DispatchIntent) error { return nil }}
	result, err := executor.Step(ctx, intent)
	if err != nil || result.Observation != "online" || result.Delivery != "uncertain" || native.calls != 1 {
		t.Fatalf("first %+v %v calls %d", result, err, native.calls)
	}
	// Same request after a lost response must never send a second command.
	result, err = executor.Step(ctx, intent)
	if err != nil || result.Delivery != "reserved" || native.calls != 1 {
		t.Fatalf("duplicate %+v %v calls %d", result, err, native.calls)
	}
	in.Rows = nil
	result, err = executor.Step(ctx, intent)
	if err != nil || result.Observation != "absent" || native.calls != 1 {
		t.Fatalf("reconcile %+v %v", result, err)
	}
}

func TestExecutionRechecksAfterReservation(t *testing.T) {
	for _, mode := range []string{"cancel", "identity", "read_failure", "journal_failure"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			in := inventory(now)
			target, _ := BindDisconnect(in, "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
			native := &testNative{}
			auth, reads := 0, 0
			ex := Executor{Journal: &testJournal{at: now}, Native: native, Now: func() time.Time { return now }, MaxAge: time.Minute,
				Authorize: func(context.Context, DispatchIntent) error {
					auth++
					if mode == "cancel" && auth == 2 {
						return errors.New("cancelled")
					}
					return nil
				},
				Read: func(context.Context) (legacy4k.OnlineInventory, error) {
					reads++
					v := inventory(now)
					if reads == 2 {
						if mode == "identity" {
							v.Rows[0]["user_name"] = "other"
						}
						if mode == "read_failure" {
							return legacy4k.OnlineInventory{}, errors.New("unavailable")
						}
					}
					return v, nil
				}}
			if mode == "journal_failure" {
				ex.Journal = failedJournal{}
			}
			_, err := ex.Step(context.Background(), DispatchIntent{Key: "one", ConnectorID: "test", Target: target, DropType: "radius"})
			if err == nil || native.calls != 0 {
				t.Fatalf("unsafe dispatch: %v calls %d", err, native.calls)
			}
		})
	}
}

type failedJournal struct{}

func (failedJournal) Lookup(context.Context, DispatchIntent) (Reservation, bool, error) {
	return Reservation{}, false, errors.New("database unavailable")
}

func (failedJournal) Cancelled(context.Context, DispatchIntent) (bool, error) {
	return false, errors.New("database unavailable")
}

func (failedJournal) Record(context.Context, DispatchIntent, StepResult, bool) error { return nil }

func (failedJournal) Reserve(context.Context, DispatchIntent) (Reservation, error) {
	return Reservation{}, errors.New("uncertain commit")
}

func TestOutcomeWriteFailureDoesNotResend(t *testing.T) {
	now := time.Now().UTC()
	in := inventory(now)
	target, _ := BindDisconnect(in, "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
	j := &testJournal{at: now, recordErr: errors.New("database unavailable")}
	native := &testNative{}
	ex := Executor{Journal: j, Native: native, Now: func() time.Time { return now }, MaxAge: time.Minute, Authorize: func(context.Context, DispatchIntent) error { return nil }, Read: func(context.Context) (legacy4k.OnlineInventory, error) { return in, nil }}
	intent := DispatchIntent{Key: "same", ConnectorID: "lab", Target: target, DropType: "radius"}
	if _, err := ex.Step(context.Background(), intent); err == nil {
		t.Fatal("outcome failure hidden")
	}
	j.recordErr = nil
	if _, err := ex.Step(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if native.calls != 1 || j.records != 2 {
		t.Fatalf("retried send or missing outcomes: calls=%d records=%d", native.calls, j.records)
	}
}

func TestPersistedCancellationStopsClaimedSender(t *testing.T) {
	now := time.Now().UTC()
	in := inventory(now)
	target, _ := BindDisconnect(in, "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
	j := &testJournal{at: now}
	native := &testNative{}
	reads := 0
	ex := Executor{Journal: j, Native: native, Now: func() time.Time { return now }, MaxAge: time.Minute, Authorize: func(context.Context, DispatchIntent) error { return nil }, Read: func(context.Context) (legacy4k.OnlineInventory, error) {
		reads++
		if reads == 2 {
			j.cancelled = true
		}
		return in, nil
	}}
	_, err := ex.Step(context.Background(), DispatchIntent{Key: "cancelled", ConnectorID: "lab", Target: target, DropType: "radius"})
	if err == nil || native.calls != 0 || !j.claimed || j.records != 1 {
		t.Fatalf("cancellation not applied after claim: err=%v calls=%d journal=%+v", err, native.calls, j)
	}
}

func TestNativeAuthenticationCannotStaleFinalAuthorization(t *testing.T) {
	for _, mode := range []string{"revoked", "rebound"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			target, _ := BindDisconnect(inventory(now), "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
			authenticated := make(chan struct{})
			var drops atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2/auth/get-access-token" {
					close(authenticated)
					io.WriteString(w, `{"code":0,"data":{"access_token":"token","lifetime":60}}`)
					return
				}
				drops.Add(1)
				io.WriteString(w, `{"code":0}`)
			}))
			defer server.Close()
			client, err := New(server.URL, "app", "secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			ex := Executor{Journal: &testJournal{at: now}, Native: client, Now: func() time.Time { return now }, MaxAge: time.Minute,
				Authorize: func(context.Context, DispatchIntent) error {
					select {
					case <-authenticated:
						if mode == "revoked" {
							return errors.New("revoked while authenticating")
						}
					default:
					}
					return nil
				},
				Read: func(context.Context) (legacy4k.OnlineInventory, error) {
					in := inventory(now)
					select {
					case <-authenticated:
						if mode == "rebound" {
							in.Rows[0]["user_name"] = "other"
						}
					default:
					}
					return in, nil
				}}
			_, err = ex.Step(context.Background(), DispatchIntent{Key: "one", ConnectorID: "test", Target: target, DropType: "radius"})
			if err == nil || drops.Load() != 0 {
				t.Fatalf("stale authorization sent a command: err=%v drops=%d", err, drops.Load())
			}
		})
	}
}

func TestRevokedAuthorizationStillReconcilesExistingDispatch(t *testing.T) {
	now := time.Now().UTC()
	target, _ := BindDisconnect(inventory(now), "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
	j := &testJournal{at: now, claimed: true, cancelled: true}
	native := &testNative{}
	ex := Executor{Journal: j, Native: native, Now: func() time.Time { return now }, MaxAge: time.Minute, Authorize: func(context.Context, DispatchIntent) error { return errors.New("revoked") }, Read: func(context.Context) (legacy4k.OnlineInventory, error) {
		in := inventory(now)
		in.Rows = nil
		return in, nil
	}}
	r, err := ex.Step(context.Background(), DispatchIntent{Key: "one", ConnectorID: "lab", Target: target, DropType: "radius"})
	if err != nil || r.Observation != "absent" || native.calls != 0 || j.records != 1 {
		t.Fatalf("revoked action could not reconcile: %+v %v", r, err)
	}
	j.claimed = false
	if _, err = ex.Step(context.Background(), DispatchIntent{Key: "new", ConnectorID: "lab", Target: target, DropType: "radius"}); err == nil || j.claimed {
		t.Fatal("revoked new action was reserved")
	}
}

func TestExecutionBusinessRejectionIsDistinctAndNeverResent(t *testing.T) {
	now := time.Now().UTC()
	in := inventory(now)
	target, _ := BindDisconnect(in, "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
	native := &testNative{err: ErrBusinessRejected}
	journal := &testJournal{at: now}
	executor := Executor{Journal: journal, Native: native, Now: func() time.Time { return now }, MaxAge: time.Minute, Read: func(context.Context) (legacy4k.OnlineInventory, error) { return in, nil }, Authorize: func(context.Context, DispatchIntent) error { return nil }}
	intent := DispatchIntent{Key: "rejected", ConnectorID: "fixture", Target: target, DropType: "radius"}
	result, err := executor.Step(context.Background(), intent)
	if err != nil || result.Delivery != "rejected" || result.Observation != "online" || native.calls != 1 {
		t.Fatalf("rejection not distinguished: %+v %v", result, err)
	}
	_, err = executor.Step(context.Background(), intent)
	if err != nil || native.calls != 1 {
		t.Fatalf("rejected operation resent: calls=%d %v", native.calls, err)
	}
}
