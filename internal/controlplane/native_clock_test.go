package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestWaitNativeObservationDoesNotAcceptFutureTime(t *testing.T) {
	at := time.Now().Add(20 * time.Millisecond)
	if err := waitNativeObservation(context.Background(), at); err != nil || time.Now().Before(at) {
		t.Fatal("future time accepted", err)
	}
	if waitNativeObservation(context.Background(), time.Now().Add(time.Second)) == nil {
		t.Fatal("large drift accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitNativeObservation(ctx, time.Now().Add(20*time.Millisecond)) == nil {
		t.Fatal("cancellation ignored")
	}
}
