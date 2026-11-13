package devicesignal

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestBoundedCaptureWriterKeepsOrderAndBlocksAtLimit(t *testing.T) {
	entered := make(chan int, 3)
	releaseFirst := make(chan struct{})
	var mu sync.Mutex
	var written []int
	writer := newBoundedCaptureWriter(1, func(value int) error {
		entered <- value
		if value == 1 {
			<-releaseFirst
		}
		mu.Lock()
		written = append(written, value)
		mu.Unlock()
		return nil
	}, func() error { return nil })
	if err := writer.submit(1); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-entered:
		if value != 1 {
			t.Fatalf("first write = %d", value)
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	if err := writer.submit(2); err != nil {
		t.Fatal(err)
	}
	thirdStarted := make(chan struct{})
	third := make(chan error, 1)
	go func() {
		close(thirdStarted)
		third <- writer.submit(3)
	}()
	<-thirdStarted
	select {
	case <-third:
		t.Fatal("third bucket entered a full queue")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseFirst)
	select {
	case err := <-third:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("third bucket remained blocked after writer advanced")
	}
	if err := writer.closeAndWait(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(written, []int{1, 2, 3}) {
		t.Fatalf("write order = %v", written)
	}
}

func TestBoundedCaptureWriterSurfacesWriteFailure(t *testing.T) {
	want := errors.New("disk write failed")
	finishCalled := false
	writer := newBoundedCaptureWriter(1, func(value int) error { return want }, func() error {
		finishCalled = true
		return nil
	})
	if err := writer.submit(1); err != nil && !errors.Is(err, want) {
		t.Fatal(err)
	}
	if err := writer.closeAndWait(); !errors.Is(err, want) {
		t.Fatalf("close error = %v, want %v", err, want)
	}
	if finishCalled {
		t.Fatal("finish ran after a failed write")
	}
}
