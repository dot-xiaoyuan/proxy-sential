package store

import (
	"context"
	"fmt"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

type Mode string

const (
	ModeFile Mode = "file"
	ModeDB   Mode = "db"
	ModeDual Mode = "dual"
)

type Query struct {
	Level    string
	Q        string
	SensorID string
	From     string
	To       string
	Limit    int
	Cursor   int
}

type Page struct {
	Limit      int
	NextCursor *string
	Total      int
}

type RiskPage struct {
	Items []risk.Snapshot
	Page  Page
}

type Run struct {
	RunID          string
	StartedAt      string
	FinishedAt     string
	SensorID       string
	PreviousOffset int64
	NewOffset      int64
	Truncated      bool
	Normalized     NormalizedCounts
	EvidenceCount  int
	RiskCount      int
	RiskListCount  int
	RawRef         map[string]any
}

type NormalizedCounts struct {
	Read      int            `json:"read"`
	Emitted   int            `json:"emitted"`
	Skipped   int            `json:"skipped"`
	Malformed int            `json:"malformed"`
	ByType    map[string]int `json:"by_type,omitempty"`
}

type Overview struct {
	LevelCounts    map[string]int
	PendingReviews int
	LatestRun      Run
	Throughput     map[string]int
	TopEvidence    []ingest.EventTypeCount
}

type AuditLog struct {
	AuditID   string
	Actor     string
	Action    string
	Target    string
	Outcome   string
	CreatedAt string
}

type Reader interface {
	Overview(ctx context.Context) (Overview, error)
	ListRisks(ctx context.Context, query Query) (RiskPage, error)
	GetIPRisk(ctx context.Context, ip string) (risk.Snapshot, error)
	GetIPEvidence(ctx context.Context, ip string) ([]evidence.Evidence, error)
	ListEventSamples(ctx context.Context, query Query) ([]normalized.Event, error)
	GetEvent(ctx context.Context, eventID string) (normalized.Event, bool, error)
	ListRuns(ctx context.Context, limit int) ([]Run, error)
	ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error)
	IngestStatus(ctx context.Context) (ingest.Status, error)
	ListIngestDiagnostics(ctx context.Context, query Query) ([]ingest.Diagnostic, error)
	ListIngestEventTypes(ctx context.Context) ([]ingest.EventTypeCount, error)
	ListIngestErrors(ctx context.Context, limit int) ([]ingest.Diagnostic, error)
}

type Writer interface {
	WriteCollectorRun(ctx context.Context, run Run) error
	WriteNormalizedEvents(ctx context.Context, events []normalized.Event) error
	WriteIngestDiagnostics(ctx context.Context, diagnostics []ingest.Diagnostic) error
	WriteEvidence(ctx context.Context, evidence []evidence.Evidence) error
	WriteRiskSnapshots(ctx context.Context, snapshots []risk.Snapshot) error
}

type ReadWriter interface {
	Reader
	Writer
}

type Options struct {
	Mode          Mode
	ShadowDir     string
	SensorID      string
	CollectorKind string
	CollectorVer  string
	InterfaceName string
	PostgresDSN   string
	ClickHouseDSN string
}

func NewReader(opts Options) (Reader, error) {
	mode := opts.Mode
	if mode == "" {
		mode = ModeFile
	}
	switch mode {
	case ModeFile:
		return NewFileStore(FileOptions{
			ShadowDir:     opts.ShadowDir,
			SensorID:      opts.SensorID,
			CollectorKind: opts.CollectorKind,
			CollectorVer:  opts.CollectorVer,
			InterfaceName: opts.InterfaceName,
			StorageMode:   string(mode),
		}), nil
	case ModeDual:
		if opts.PostgresDSN != "" && opts.ClickHouseDSN != "" {
			return NewDBStore(opts)
		}
		return NewFileStore(FileOptions{
			ShadowDir:     opts.ShadowDir,
			SensorID:      opts.SensorID,
			CollectorKind: opts.CollectorKind,
			CollectorVer:  opts.CollectorVer,
			InterfaceName: opts.InterfaceName,
			StorageMode:   string(mode),
		}), nil
	case ModeDB:
		return NewDBStore(opts)
	default:
		return nil, fmt.Errorf("unknown storage mode: %s", mode)
	}
}

func NewWriter(opts Options) (Writer, error) {
	mode := opts.Mode
	if mode == "" {
		mode = ModeFile
	}
	switch mode {
	case ModeFile:
		return NoopWriter{}, nil
	case ModeDual:
		if opts.PostgresDSN == "" && opts.ClickHouseDSN == "" {
			return NoopWriter{}, nil
		}
		return NewDBStore(opts)
	case ModeDB:
		return NewDBStore(opts)
	default:
		return nil, fmt.Errorf("unknown storage mode: %s", mode)
	}
}

func NowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

type NoopWriter struct{}

func (NoopWriter) WriteCollectorRun(context.Context, Run) error {
	return nil
}

func (NoopWriter) WriteNormalizedEvents(context.Context, []normalized.Event) error {
	return nil
}

func (NoopWriter) WriteIngestDiagnostics(context.Context, []ingest.Diagnostic) error {
	return nil
}

func (NoopWriter) WriteEvidence(context.Context, []evidence.Evidence) error {
	return nil
}

func (NoopWriter) WriteRiskSnapshots(context.Context, []risk.Snapshot) error {
	return nil
}
