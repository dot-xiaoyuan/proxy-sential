package store

import "time"

// chCursorRow 是 ClickHouse 事件流上的一行续读键。
type chCursorRow struct {
	Stamp   time.Time
	EventID string
}

// chRowAfterCursor 表达 ClickHouse 谓词不再表达的精确续读点。
//
// 事件流的读取谓词刻意只保留时间下界（`received_at >= 游标`），因为元组比较
// `(received_at,event_id) > (游标,event_id)` 会让 ClickHouse 放弃
// (sensor_id,received_at,event_id) 主键索引：现场实测同一批 200 行从 46.6 秒降到
// 13.8 秒，读到的 granule 从 81% 降到个位数百分比。精确续读点因此改在 Go 侧判定，
// 只有与游标同一时间戳的行会走到这里，批次仍能前进。
func chRowAfterCursor(stamp time.Time, eventID string, cursorStamp time.Time, cursorEventID string) bool {
	if cursorStamp.IsZero() {
		return true
	}
	if stamp.After(cursorStamp) {
		return true
	}
	return stamp.Equal(cursorStamp) && eventID > cursorEventID
}

// chAdvanceCursor 把游标推进到 candidate，但绝不后退。返回推进后的键与是否前进。
// 只允许前进是为了让「同一时间戳的整批都被续读点过滤掉」这种病态情况退化为不推进，
// 而不是把游标回退成死循环。
func chAdvanceCursor(current time.Time, currentEventID string, candidate chCursorRow) (time.Time, string, bool) {
	if !chRowAfterCursor(candidate.Stamp, candidate.EventID, current, currentEventID) {
		return current, currentEventID, false
	}
	return candidate.Stamp, candidate.EventID, true
}

// chBoundKey 是 ClickHouse 续读键的一列：列表达式与已经转义好的字面量。
// Value 由调用方负责转义或写成函数调用，本函数只拼接。
type chBoundKey struct {
	Expr  string
	Value string
}

// chAfterBound 生成与元组比较等价的「严格在游标之后」谓词，同时保持主键索引可用：
//
//	a>v1 OR (a=v1 AND (b>v2 OR (b=v2 AND c>v3)))
//
// 元组比较 (a,b,c)>(v1,v2,v3) 会让 ClickHouse 的主键索引分析提取不到 key range，
// 现场实测 router_signal_events_v1 上同一批 2000 行从 1.9 秒退化到 41.6 秒，
// 扫描的 granule 从 18/3263 变成 3263/3263。
//
// 调用方还应同时给出首列下界（`a>=v1`），让分区裁剪先于主键裁剪发生。
func chAfterBound(keys []chBoundKey) string {
	if len(keys) == 0 {
		return "1"
	}
	head := keys[0]
	if len(keys) == 1 {
		return head.Expr + ">" + head.Value
	}
	return head.Expr + ">" + head.Value + " OR (" + head.Expr + "=" + head.Value + " AND (" + chAfterBound(keys[1:]) + "))"
}
