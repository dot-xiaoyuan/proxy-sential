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
