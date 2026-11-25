package main

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"proxy-sentinel/internal/devicesignal"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
)

func TestHandshakePriorityKeepsLastSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := &normalized.CaptureScope{ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
	key := sharedaccess.OutletKey{IP: netip.MustParseAddr("192.0.2.2"), MAC: [6]byte{2, 0, 0, 0, 0, 1}}
	var stage atomic.Int32
	read := func(context.Context, string, string, string) (map[sharedaccess.OutletKey]struct{}, error) {
		switch stage.Load() {
		case 1:
			return map[sharedaccess.OutletKey]struct{}{key: {}}, nil
		case 3:
			return map[sharedaccess.OutletKey]struct{}{}, nil
		default:
			return nil, errors.New("lookup failed")
		}
	}
	snapshot := handshakeRouterPriority(ctx, scope, 5*time.Millisecond, read)
	wait := func(stageNum int32, wantKeys int, failed, reused bool) {
		t.Helper()
		stage.Store(stageNum)
		until := time.Now().Add(time.Second)
		var got devicesignal.RouterSamplingSnapshot
		for time.Now().Before(until) {
			got = snapshot()
			_, present := got.Keys[key]
			if present == (wantKeys > 0) && len(got.Keys) == wantKeys && got.LookupFailed == failed && got.ReusedPreviousList == reused {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("stage %d: unexpected priority snapshot %+v", stageNum, got)
	}
	wait(0, 0, true, false)
	wait(1, 1, false, false)
	wait(2, 1, true, true)
	wait(3, 0, false, false)
}
