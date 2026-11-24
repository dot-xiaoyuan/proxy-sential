package sharedaccess

import "time"

// CoverageV2 describes a measured interval, including deliberate output loss.
// An empty IP applies to the entire registered capture scope, never one device.
type CoverageV2 struct {
	SchemaVersion    string    `json:"schema_version"`
	From             time.Time `json:"covered_from"`
	To               time.Time `json:"covered_to"`
	KernelStatsKnown bool      `json:"kernel_stats_known"`
	Received         uint64    `json:"received_packets,omitempty"`
	Dropped          uint64    `json:"dropped_packets"`
	QueueFreezes     uint64    `json:"queue_freezes,omitempty"`
	ParseUnknown     int       `json:"unscoped_parse_truncated"`
	ExcludedFrames   int       `json:"excluded_frames,omitempty"`
	Truncated        int       `json:"parse_truncated"`
	Overflow         int       `json:"feature_overflow"`
	Omitted          int       `json:"output_omitted"`
	KeyDrops         int       `json:"key_drops"`
	Stopped          bool      `json:"stopped"`
	// MetadataOmitted counts excess values in optional display fields. The
	// separately bounded structured samples determine detection coverage.
	MetadataOmitted int `json:"metadata_omitted,omitempty"`
}

func (c CoverageV2) Complete() bool {
	return c.SchemaVersion == "capture-coverage/v2" && !c.From.IsZero() && c.To.After(c.From) && c.KernelStatsKnown && c.Dropped == 0 && c.QueueFreezes == 0 && c.ParseUnknown == 0 && c.Truncated == 0 && c.Overflow == 0 && c.Omitted == 0 && c.KeyDrops == 0 && !c.Stopped
}

type HandshakeSample struct {
	ClientOuterVLAN uint16    `json:"client_outer_vlan,omitempty"`
	ClientVLAN      uint16    `json:"client_vlan,omitempty"`
	ClientTTL       uint8     `json:"client_ttl,omitempty"`
	Bucket          int64     `json:"five_second_bucket"`
	Family          string    `json:"family"`
	Value           string    `json:"value"`
	EventID         string    `json:"event_id"`
	ObservedAt      time.Time `json:"observed_at"`
	DestinationPort uint16    `json:"dst_port,omitempty"`
}
