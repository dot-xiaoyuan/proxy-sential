package store

import "testing"

// 元组比较会让 ClickHouse 放弃主键索引；生成器必须产生等价的括号化析取式。
func TestChAfterBoundKeepsLexicographicSemantics(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []chBoundKey
		want string
	}{
		{"single", []chBoundKey{{"timestamp", "T"}}, "timestamp>T"},
		{"pair", []chBoundKey{{"timestamp", "T"}, {"event_id", "E"}}, "timestamp>T OR (timestamp=T AND (event_id>E))"},
		{"triple", []chBoundKey{{"timestamp", "T"}, {"sensor_id", "S"}, {"event_id", "E"}}, "timestamp>T OR (timestamp=T AND (sensor_id>S OR (sensor_id=S AND (event_id>E))))"},
		{"empty", nil, "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := chAfterBound(tc.keys); got != tc.want {
				t.Fatalf("chAfterBound() = %q, want %q", got, tc.want)
			}
		})
	}
}
