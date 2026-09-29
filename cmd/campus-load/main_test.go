package main

import (
	"context"
	"testing"
	"time"
)

func TestAllLocalProtocolsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := run(ctx, 30, 4, 1000)
	if err != nil || r.Success != 30 || r.Failed != 0 || r.DNS != 10 || r.HTTP != 10 || r.TLS != 10 {
		t.Fatalf("protocol validation failed: %+v %v", r, err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	r, err = run(cancelled, 10000, 2, 100)
	if err != nil || r.Requests != 0 {
		t.Fatalf("cancelled load continued: %+v %v", r, err)
	}
}
