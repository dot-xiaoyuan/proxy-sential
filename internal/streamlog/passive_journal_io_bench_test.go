package streamlog

import "testing"

// This separates the local v1 journal phases without changing their durable
// barriers. Results measure the developer's filesystem, not the shared HDD in
// the test environment. Run with -benchtime=12x to keep disk use bounded.
func BenchmarkPassiveJournalPhases(b *testing.B) {
	for _, phase := range []string{"append", "commit", "release"} {
		b.Run(phase, func(b *testing.B) {
			j, err := Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			base := encodingSegment(500)
			base.Source = "passive-discovery"
			base.SourcePath = "packet://bond0/sensor"
			base.ParserVersion = "passive-frame-v1"
			base.PreviousOffset, base.StartOffset, base.EndOffset = 0, 0, 4096
			if err := j.StartFreshSource(SourceCursor{
				Epoch: base.Epoch, Source: base.Source, Path: base.SourcePath,
				FileID: base.FileID, ParserVersion: base.ParserVersion,
			}); err != nil {
				b.Fatal(err)
			}
			var offset int64
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				segment := base
				segment.PreviousOffset, segment.StartOffset = offset, offset
				segment.EndOffset = offset + 4096
				b.StopTimer()
				if phase == "append" {
					b.StartTimer()
				}
				id, err := j.Append(segment)
				if phase == "append" {
					b.StopTimer()
				}
				if err != nil {
					b.Fatal(err)
				}
				if phase == "commit" {
					b.StartTimer()
				}
				err = j.CommitSource(segment.Source, segment.SourcePath, id)
				if phase == "commit" {
					b.StopTimer()
				}
				if err != nil {
					b.Fatal(err)
				}
				if phase == "release" {
					for _, lane := range []Lane{Archive, Search, Projection} {
						if err := j.Ack(id, lane); err != nil {
							b.Fatal(err)
						}
					}
					b.StartTimer()
					err = j.Release(id)
					b.StopTimer()
					if err != nil {
						b.Fatal(err)
					}
				}
				offset = segment.EndOffset
			}
		})
	}
}
