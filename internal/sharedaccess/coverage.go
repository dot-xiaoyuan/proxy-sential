package sharedaccess

import "time"

// CoverageV2 describes a measured interval, including deliberate output loss.
// An empty IP applies to the entire registered capture scope, never one device.
type CoverageV2 struct {
	SchemaVersion    string    `json:"schema_version"`
	From             time.Time `json:"covered_from"`
	To               time.Time `json:"covered_to"`
	KernelStatsKnown bool      `json:"kernel_stats_known"`
	Dropped          uint64    `json:"dropped_packets"`
	ParseUnknown     int       `json:"unscoped_parse_truncated"`
	Truncated        int       `json:"parse_truncated"`
	Overflow         int       `json:"feature_overflow"`
	Omitted          int       `json:"output_omitted"`
	KeyDrops         int       `json:"key_drops"`
	Stopped          bool      `json:"stopped"`
}

func (c CoverageV2) Complete() bool {
	return c.SchemaVersion == "capture-coverage/v2" && !c.From.IsZero() && c.To.After(c.From) && c.KernelStatsKnown && c.Dropped == 0 && c.ParseUnknown == 0 && c.Truncated == 0 && c.Overflow == 0 && c.Omitted == 0 && c.KeyDrops == 0 && !c.Stopped
}

type HandshakeSample struct {
	Bucket     int64     `json:"five_second_bucket"`
	Family     string    `json:"family"`
	Value      string    `json:"value"`
	EventID    string    `json:"event_id"`
	ObservedAt time.Time `json:"observed_at"`
}
