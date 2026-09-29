package ingest

type Collector struct {
	Kind      string `json:"kind"`
	Version   string `json:"version,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type Diagnostic struct {
	SchemaVersion string         `json:"schema_version"`
	DiagnosticID  string         `json:"diagnostic_id"`
	Timestamp     string         `json:"timestamp"`
	SensorID      string         `json:"sensor_id"`
	Collector     Collector      `json:"collector"`
	Stage         string         `json:"stage"`
	Type          string         `json:"type"`
	Severity      string         `json:"severity"`
	Summary       string         `json:"summary"`
	Counters      map[string]int `json:"counters,omitempty"`
	ByType        map[string]int `json:"by_type,omitempty"`
	RawRef        map[string]any `json:"raw_ref,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}

type Status struct {
	SensorID          string         `json:"sensor_id"`
	Collector         Collector      `json:"collector"`
	StorageMode       string         `json:"storage_mode"`
	LatestRunID       string         `json:"latest_run_id"`
	LatestRunAt       string         `json:"latest_run_at"`
	Healthy           bool           `json:"healthy"`
	Severity          string         `json:"severity"`
	Summary           string         `json:"summary"`
	LastCounters      map[string]int `json:"last_counters"`
	LastEventTypeDist map[string]int `json:"last_event_type_dist"`
}

type EventTypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type Checkpoint struct {
	SensorID    string `json:"sensor_id"`
	SourceKind  string `json:"source_kind"`
	SourcePath  string `json:"source_path"`
	FileID      string `json:"file_id"`
	Offset      int64  `json:"committed_offset"`
	LastEventAt string `json:"last_event_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type Batch struct {
	BatchID     string `json:"batch_id"`
	SensorID    string `json:"sensor_id"`
	SourceKind  string `json:"source_kind"`
	SourcePath  string `json:"source_path"`
	FileID      string `json:"file_id"`
	StartOffset int64  `json:"start_offset"`
	EndOffset   int64  `json:"end_offset"`
	Checksum    string `json:"checksum"`
	Status      string `json:"status"`
	EventCount  int    `json:"event_count"`
	Malformed   int    `json:"malformed_count"`
	LastError   string `json:"last_error,omitempty"`
	StartedAt   string `json:"started_at"`
	CommittedAt string `json:"committed_at,omitempty"`
}
