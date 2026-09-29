package appdomain

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

func TestSixApplicationReplayBoundaries(t *testing.T) {
	raw, err := ExampleBundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/application-domain/matching-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Domain string `json:"domain"`
		Kind   string `json:"target_type"`
		ID     string `json:"target_id"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, tc := range vectors {
		m := b.Match(tc.Domain)
		if m.TargetType != tc.Kind || m.TargetID != tc.ID {
			t.Errorf("%s: %+v", tc.Domain, m)
		}
	}

}
func TestConcurrentLibrarySwitch(t *testing.T) {
	m, _ := OpenManager(t.TempDir())
	if err := m.Import(testBundle(t, "v1")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b, _ := m.Snapshot()
				if b.Match("a.weixin.qq.com").TargetID != "wechat" {
					t.Error("mixed snapshot")
				}
				_ = m.Status()
			}
		}()
	}
	if err := m.Import(testBundle(t, "v2")); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}
