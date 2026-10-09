package controlplane

import (
	"sync"
	"testing"
)

func TestNativeRuntimeRefreshEpochRejectsOlderCredentialRead(t *testing.T) {
	s := &Server{nativeActionsMu: &sync.RWMutex{}}
	s.setNativeRuntime("one", NativeActionRuntime{TestAccount: "original"})
	old := s.invalidateNativeRuntime("one")
	if _, ok := s.nativeRuntime("one"); ok {
		t.Fatal("invalidated runtime still available")
	}
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	go func() {
		close(started)
		<-finish
		done <- s.setNativeRuntimeAtEpoch("one", old, &NativeActionRuntime{TestAccount: "stale"})
	}()
	<-started
	current := s.invalidateNativeRuntime("one")
	if !s.setNativeRuntimeAtEpoch("one", current, &NativeActionRuntime{TestAccount: "new"}) {
		t.Fatal("current refresh rejected")
	}
	close(finish)
	if <-done {
		t.Fatal("older credential read overwrote new configuration")
	}
	runtime, ok := s.nativeRuntime("one")
	if !ok || runtime.TestAccount != "new" {
		t.Fatalf("runtime=%+v available=%v", runtime, ok)
	}
	if s.setNativeRuntimeAtEpoch("one", current, &NativeActionRuntime{TestAccount: "replay"}) {
		t.Fatal("refresh lease reused")
	}
}

func TestNativeRuntimeExplicitConfigurationAndFailedRefreshInvalidateLease(t *testing.T) {
	s := &Server{nativeActionsMu: &sync.RWMutex{}}
	epoch := s.invalidateNativeRuntime("one")
	s.setNativeRuntime("one", NativeActionRuntime{TestAccount: "explicit"})
	if s.setNativeRuntimeAtEpoch("one", epoch, &NativeActionRuntime{TestAccount: "stale"}) {
		t.Fatal("refresh replaced explicitly provisioned runtime")
	}
	failed := s.invalidateNativeRuntime("one")
	if !s.setNativeRuntimeAtEpoch("one", failed, nil) {
		t.Fatal("failed refresh not consumed")
	}
	if _, ok := s.nativeRuntime("one"); ok {
		t.Fatal("failed refresh retained old controller credentials")
	}
	if s.setNativeRuntimeAtEpoch("one", failed, &NativeActionRuntime{}) {
		t.Fatal("failed refresh lease reused")
	}
}
