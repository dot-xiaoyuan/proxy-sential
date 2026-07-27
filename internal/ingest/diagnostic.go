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
