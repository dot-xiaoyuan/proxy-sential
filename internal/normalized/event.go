package normalized

type Event struct {
	SchemaVersion   string         `json:"schema_version"`
	EventID         string         `json:"event_id"`
	Source          string         `json:"source"`
	SourceEventType string         `json:"source_event_type,omitempty"`
	Type            string         `json:"type"`
	Timestamp       string         `json:"timestamp"`
	Observer        map[string]any `json:"observer,omitempty"`
	Subject         map[string]any `json:"subject"`
	Flow            map[string]any `json:"flow"`
	Payload         map[string]any `json:"payload,omitempty"`
	Confidence      float64        `json:"confidence"`
	RawRef          map[string]any `json:"raw_ref,omitempty"`
}
