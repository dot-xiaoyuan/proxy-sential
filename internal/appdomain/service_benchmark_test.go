package appdomain

import (
	"fmt"
	"testing"
	"time"
)

// Measures a fixed incoming page against increasing retained history. This
// catches algorithms whose cost multiplies full history by the shard count.
func BenchmarkPersistApplicationPage(b *testing.B) {
	for _, size := range []int{10000, 100000} {
		b.Run(fmt.Sprintf("retained_%d_page_1000", size), func(b *testing.B) {
			s, err := OpenService(b.TempDir(), nil)
			if err != nil {
				b.Fatal(err)
			}
			now := time.Now().UTC()
			for i := 0; i < size; i++ {
				event := fixtureEvent(fmt.Sprintf("seed-%d", i), "tls", "service.example.com", "", nil)
				event.Timestamp = now.Format(time.RFC3339Nano)
				o := Observe(event, nil)
				s.rows[o.Key()] = o
			}
			changed := map[string]Observation{}
			for i := 0; i < 1000; i++ {
				event := fixtureEvent(fmt.Sprintf("new-%d", i), "tls", "service.example.com", "", nil)
				event.Timestamp = now.Format(time.RFC3339Nano)
				o := Observe(event, nil)
				changed[o.Key()] = o
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.persistRows(changed, now.Add(-7*24*time.Hour)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
