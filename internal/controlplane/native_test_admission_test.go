package controlplane

import "testing"

func TestNativeTestExceptionRequiresLoopbackAndExactIdentity(t *testing.T) {
	m := map[string]NativeActionRuntime{"c": {TestAccount: "yuantong", CampusID: "test190", AccessDomain: "srun190"}}
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "192.168.0.30:8080", "localhost:8080"} {
		if ValidateNativeTestListener(m, addr) == nil {
			t.Fatalf("unsafe bind accepted %s", addr)
		}
	}
	if err := ValidateNativeTestListener(m, "127.0.0.1:28080"); err != nil {
		t.Fatal(err)
	}
	s := &Server{nativeActions: m}
	if !s.nativeTestAccountAllowed("c", "yuantong", "test190", "srun190") {
		t.Fatal("test account rejected")
	}
	for _, v := range [][4]string{{"c", "other", "test190", "srun190"}, {"c", "yuantong", "office", "srun190"}, {"c", "yuantong", "test190", "other"}, {"other", "yuantong", "test190", "srun190"}} {
		if s.nativeTestAccountAllowed(v[0], v[1], v[2], v[3]) {
			t.Fatal("scope bypass")
		}
	}
}
