package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"proxy-sentinel/internal/legacy4k"
)

// Cancel through a real context at a deterministic work boundary; tests never
// depend on CPU speed or timing between goroutines.
type identityBoundaryCancel struct {
	context.Context
	cancel        context.CancelFunc
	checks, limit int
}

func (c *identityBoundaryCancel) Err() error {
	c.checks++
	if c.checks >= c.limit {
		c.cancel()
	}
	return c.Context.Err()
}

func identityWorkContext(limit int) *identityBoundaryCancel {
	ctx, cancel := context.WithCancel(context.Background())
	return &identityBoundaryCancel{Context: ctx, cancel: cancel, limit: limit}
}

// Frozen r66 JSON hashing is an independent reference, not the streaming code.
func snapshotIDJSONReference(request identitySnapshotRequest) (string, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "srun4k-identity-" + hex.EncodeToString(digest[:])[:32], nil
}

func TestIdentityLocalPreparationStopsWithoutPartialEvents(t *testing.T) {
	for _, limit := range []int{1, 3, 8, 25, 82} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			request := snapshotConversionFixture(40)
			before, _ := json.Marshal(request)
			ctx := identityWorkContext(limit)
			defer ctx.cancel()
			got, err := prepareIdentitySnapshotContext(ctx, request, "cancel-replay", request.ObservedAt.Add(time.Minute), legacy4k.MaxIdentityAddressRecords)
			if !errors.Is(err, context.Canceled) || len(got.Events) != 0 {
				t.Fatalf("cancelled work published events=%d checks=%d err=%v", len(got.Events), ctx.checks, err)
			}
			after, _ := json.Marshal(request)
			if !bytes.Equal(before, after) {
				t.Fatal("input records mutated")
			}
			if ctx.checks > limit+1 {
				t.Fatal("continued processing after cancellation")
			}
		})
	}
}

func TestIdentityLocalPreparationDeadlineRetainsCause(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	request := snapshotConversionFixture(2)
	got, err := prepareIdentitySnapshotContext(ctx, request, "deadline-replay", request.ObservedAt.Add(time.Minute), 200000)
	if !errors.Is(err, context.DeadlineExceeded) || len(got.Events) != 0 {
		t.Fatalf("expired work published events=%d err=%v", len(got.Events), err)
	}
}

func TestIdentityHashInterruptedNeverPublishesID(t *testing.T) {
	for _, limit := range []int{1, 3, 8, 25, 82} {
		ctx := identityWorkContext(limit)
		id, err := srunIdentitySnapshotIDContext(ctx, snapshotConversionFixture(40))
		ctx.cancel()
		if id != "" || !errors.Is(err, context.Canceled) {
			t.Fatalf("hash published partial id=%q checks=%d err=%v", id, ctx.checks, err)
		}
		if ctx.checks > limit+1 {
			t.Fatal("hash continued after cancellation")
		}
	}
}

func TestIdentityHashDeadlineRetainsCause(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	id, err := srunIdentitySnapshotIDContext(ctx, snapshotConversionFixture(2))
	if id != "" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired hash published %q %v", id, err)
	}
}

func TestIdentityHashMatchesFrozenJSONSemantics(t *testing.T) {
	for _, name := range []string{"ordinary", "empty", "nil", "nil_record", "escaped", "invalid_utf8", "optional_scope", "time_offset", "expected_null", "zero_time"} {
		t.Run(name, func(t *testing.T) {
			request := snapshotConversionFixture(4)
			switch name {
			case "empty":
				request.Records = []map[string]string{}
			case "nil":
				request.Records = nil
			case "nil_record":
				request.Records[2] = nil
			case "escaped":
				request.Records[2]["<escaped&key>"] = "quotes\"\n\t\x00\\\u2028\u2029中"
				request.Source = "srun4k:<&>"
			case "invalid_utf8":
				request.Records[1]["bad\xff"] = "\xff\xfe"
				request.Records[1]["bad\xfe"] = "other"
				request.Source = "srun4k:\xff"
			case "optional_scope":
				request.CampusID = "校区"
				request.AccessDomain = "WLAN"
			case "time_offset":
				request.ObservedAt = request.ObservedAt.In(time.FixedZone("fixture", 3600))
			case "expected_null":
				request.ExpectedCount = nil
			case "zero_time":
				request.ObservedAt = time.Time{}
			}
			before, _ := json.Marshal(request)
			expected, err := snapshotIDJSONReference(request)
			if err != nil {
				t.Fatal(err)
			}
			got, err := srunIdentitySnapshotIDContext(context.Background(), request)
			if err != nil || got != expected {
				t.Fatalf("id=%q want=%q err=%v", got, expected, err)
			}
			after, _ := json.Marshal(request)
			if !bytes.Equal(before, after) {
				t.Fatal("hash mutated input")
			}
		})
	}
}

func TestIdentityHashRejectsUnencodableObservation(t *testing.T) {
	request := snapshotConversionFixture(2)
	request.ObservedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := srunIdentitySnapshotIDContext(context.Background(), request)
	if got != "" || err == nil {
		t.Fatalf("invalid observation got stable id=%q err=%v", got, err)
	}
}

func TestIdentityRequestCancellationDoesNotReachStorage(t *testing.T) {
	for _, name := range []string{"cancelled", "deadline"} {
		t.Run(name, func(t *testing.T) {
			request := snapshotConversionFixture(2)
			request.ObservedAt = time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
			raw, _ := json.Marshal(request)
			reader := &snapshotReader{}
			server := &Server{reader: reader, identityIngest: &identityIngestState{key: "token"}, identitySources: []identitySourceRegistration{{IdentityScope: request.IdentityScope, IntervalSeconds: request.IntervalSeconds}}}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/snapshots", bytes.NewReader(raw))
			req.Header.Set("Authorization", "Bearer token")
			req.Header.Set("Idempotency-Key", "cancelled-http")
			var ctx context.Context
			var cancel context.CancelFunc
			if name == "cancelled" {
				ctx, cancel = context.WithCancel(req.Context())
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(req.Context(), time.Now().Add(-time.Second))
			}
			defer cancel()
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			server.handleIdentitySnapshot(w, req)
			if w.Code != http.StatusRequestTimeout || reader.commits != 0 {
				t.Fatalf("interrupted request reached storage: status=%d commits=%d body=%s", w.Code, reader.commits, w.Body.String())
			}
		})
	}
}

func BenchmarkIdentitySnapshotHash(b *testing.B) {
	request := snapshotConversionFixture(2000)
	for _, version := range []string{"json_reference", "current"} {
		b.Run(version, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				if version == "json_reference" {
					_, err = snapshotIDJSONReference(request)
				} else {
					_, err = srunIdentitySnapshotIDContext(context.Background(), request)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestIdentityLocalWorkNativeMaximum(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_LOCAL_MAXIMUM") != "1" {
		t.Skip("explicit isolated maximum identity acceptance required")
	}
	request := snapshotConversionFixture(legacy4k.MaxIdentityAddressRecords)
	expected, err := snapshotIDJSONReference(request)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	id, err := srunIdentitySnapshotIDContext(context.Background(), request)
	if err != nil || id != expected {
		t.Fatalf("maximum ID mismatch err=%v", err)
	}
	t.Logf("200000-record streaming hash matches r66 JSON id in %s", time.Since(started))
	got, err := prepareIdentitySnapshotContext(context.Background(), request, id, request.ObservedAt.Add(time.Minute), legacy4k.MaxIdentityAddressRecords)
	if err != nil || len(got.Events) != legacy4k.MaxIdentityAddressRecords {
		t.Fatalf("maximum events=%d err=%v", len(got.Events), err)
	}
	ctx := identityWorkContext(1024)
	defer ctx.cancel()
	partial, err := prepareIdentitySnapshotContext(ctx, request, id, request.ObservedAt.Add(time.Minute), legacy4k.MaxIdentityAddressRecords)
	if !errors.Is(err, context.Canceled) || len(partial.Events) != 0 || !reflect.DeepEqual(partial.IdentityScope, request.IdentityScope) {
		t.Fatal("maximum interruption published a partial inventory")
	}
}
