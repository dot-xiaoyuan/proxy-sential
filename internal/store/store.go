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
	Level       string
	Q           string
	SensorID    string
	From        string
	To          string
	Window      string
	SrcIP       string
	DstIP       string
	Domain      string
	UserAgent   string
	Fingerprint string
	Port        int
	Proto       string
	Limit       int
	Cursor      int
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

type EventPage struct {
	Items []normalized.Event
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

type ActivityProfile struct {
	IP                 string           `json:"ip"`
	Window             string           `json:"window"`
	EventCount         int              `json:"event_count"`
	FirstSeen          string           `json:"first_seen,omitempty"`
	LastSeen           string           `json:"last_seen,omitempty"`
	EventTypeCounts    []ActivityCount  `json:"event_type_counts"`
	ProtocolCounts     []ActivityCount  `json:"protocol_counts"`
	TopDomains         []ActivityCount  `json:"top_domains"`
	TopHTTPHosts       []ActivityCount  `json:"top_http_hosts"`
	TopTLSSNI          []ActivityCount  `json:"top_tls_sni"`
	TopUserAgents      []ActivityCount  `json:"top_user_agents"`
	TopTLSFingerprints []ActivityCount  `json:"top_tls_fingerprints"`
	TopDstPorts        []ActivityCount  `json:"top_dst_ports"`
	TopDstIPs          []ActivityCount  `json:"top_dst_ips"`
	RecentAccesses     []ActivityAccess `json:"recent_accesses"`
}

type ActivityQuery struct {
	SensorID string
	Window   string
	Limit    int
}

type ActivityOverview struct {
	SensorID           string              `json:"sensor_id"`
	Window             string              `json:"window"`
	EventCount         int                 `json:"event_count"`
	ActiveIPCount      int                 `json:"active_ip_count"`
	AccessObjectCount  int                 `json:"access_object_count"`
	ActiveRiskIPCount  int                 `json:"active_risk_ip_count"`
	FirstSeen          string              `json:"first_seen,omitempty"`
	LastSeen           string              `json:"last_seen,omitempty"`
	EventTypeCounts    []ActivityCount     `json:"event_type_counts"`
	ProtocolCounts     []ActivityCount     `json:"protocol_counts"`
	TopDomains         []ActivityCount     `json:"top_domains"`
	TopHTTPHosts       []ActivityCount     `json:"top_http_hosts"`
	TopTLSSNI          []ActivityCount     `json:"top_tls_sni"`
	TopUserAgents      []ActivityCount     `json:"top_user_agents"`
	TopTLSFingerprints []ActivityCount     `json:"top_tls_fingerprints"`
	TopDstPorts        []ActivityCount     `json:"top_dst_ports"`
	TopDstIPs          []ActivityCount     `json:"top_dst_ips"`
	TopSourceIPs       []ActivityCount     `json:"top_source_ips"`
	TopActiveRiskIPs   []ActivityIPSummary `json:"top_active_risk_ips"`
}

type ActivityIPSummary struct {
	IP         string          `json:"ip"`
	EventCount int             `json:"event_count"`
	RiskLevel  string          `json:"risk_level"`
	Score      int             `json:"score"`
	TopDomains []ActivityCount `json:"top_domains"`
	LastSeen   string          `json:"last_seen,omitempty"`
}

type ActivityCount struct {
	Value    string `json:"value"`
	Count    int    `json:"count"`
	LastSeen string `json:"last_seen,omitempty"`
}

type ActivityAccess struct {
	Timestamp  string `json:"timestamp"`
	EventID    string `json:"event_id"`
	Type       string `json:"type"`
	TargetKind string `json:"target_kind"`
	Target     string `json:"target"`
	Method     string `json:"method,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	DstIP      string `json:"dst_ip,omitempty"`
	DstPort    int    `json:"dst_port,omitempty"`
	Proto      string `json:"proto,omitempty"`
}

type DPIOverview struct {
	SensorID                 string `json:"sensor_id"`
	Window                   string `json:"window"`
	EventCount               int    `json:"event_count"`
	ActiveIPCount            int    `json:"active_ip_count"`
	ProtocolFlowCount        int    `json:"protocol_flow_count"`
	FingerprintConflictCount int    `json:"fingerprint_conflict_count"`
	FlowSampleCount          int    `json:"flow_sample_count"`
	FirstSeen                string `json:"first_seen,omitempty"`
	LastSeen                 string `json:"last_seen,omitempty"`
}

type DPITrendPoint struct {
	Time          string   `json:"time"`
	ActiveDevices int      `json:"active_devices"`
	RiskIPs       int      `json:"risk_ips"`
	EventCount    int      `json:"event_count"`
	PPS           *float64 `json:"pps"`
	BPSMbps       *float64 `json:"bps_mbps"`
	CPS           float64  `json:"cps"`
	Estimated     bool     `json:"estimated"`
}

type DPIProtocolFlow struct {
	Protocol     string   `json:"protocol"`
	AppProtocol  string   `json:"app_protocol"`
	Category     string   `json:"category"`
	SharePercent float64  `json:"share_percent"`
	EventCount   int      `json:"event_count"`
	BPSMbps      *float64 `json:"bps_mbps,omitempty"`
	TopApps      []string `json:"top_apps"`
}

type DPIFingerprintConflict struct {
	ID              string   `json:"id"`
	IP              string   `json:"ip"`
	ConflictType    string   `json:"conflict_type"`
	TypeLabel       string   `json:"type_label"`
	RiskLevel       string   `json:"risk_level"`
	Confidence      float64  `json:"confidence"`
	DeviceCount     int      `json:"device_count"`
	DetectedSamples []string `json:"detected_samples"`
	Reason          string   `json:"reason"`
	LastSeen        string   `json:"last_seen"`
}

type DPIFlowSample struct {
	FlowID         string `json:"flow_id"`
	EventID        string `json:"event_id"`
	Timestamp      string `json:"timestamp"`
	SensorID       string `json:"sensor_id,omitempty"`
	InterfaceName  string `json:"interface_name,omitempty"`
	SrcIP          string `json:"src_ip,omitempty"`
	SrcPort        int    `json:"src_port,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	DstPort        int    `json:"dst_port,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	AppProtocol    string `json:"app_protocol"`
	UserAgent      string `json:"user_agent,omitempty"`
	TLSSNI         string `json:"tls_sni,omitempty"`
	Domain         string `json:"domain,omitempty"`
	JA3            string `json:"ja3,omitempty"`
	JA4            string `json:"ja4,omitempty"`
	TTL            *int   `json:"ttl,omitempty"`
	IPID           *int   `json:"ipid,omitempty"`
	PayloadSummary string `json:"payload_summary"`
}

type DPIFlowDetail struct {
	Flow     DPIFlowSample       `json:"flow"`
	Event    normalized.Event    `json:"event"`
	Risk     risk.Snapshot       `json:"risk"`
	Evidence []evidence.Evidence `json:"evidence"`
}

type DPIFlowPage struct {
	Items []DPIFlowSample `json:"items"`
	Page  Page            `json:"page"`
}

type Reader interface {
	Overview(ctx context.Context) (Overview, error)
	ListRisks(ctx context.Context, query Query) (RiskPage, error)
	GetIPRisk(ctx context.Context, ip string) (risk.Snapshot, error)
	GetIPEvidence(ctx context.Context, ip string) ([]evidence.Evidence, error)
	GetIPActivity(ctx context.Context, ip string, limit int) (ActivityProfile, error)
	GetActivityOverview(ctx context.Context, query ActivityQuery) (ActivityOverview, error)
	GetDPIOverview(ctx context.Context, query ActivityQuery) (DPIOverview, error)
	ListDPITrends(ctx context.Context, query ActivityQuery) ([]DPITrendPoint, error)
	ListDPIProtocolFlows(ctx context.Context, query ActivityQuery) ([]DPIProtocolFlow, error)
	ListDPIFingerprintConflicts(ctx context.Context, query ActivityQuery) ([]DPIFingerprintConflict, error)
	ListDPIFlows(ctx context.Context, query Query) (DPIFlowPage, error)
	GetDPIFlow(ctx context.Context, flowID string) (DPIFlowDetail, bool, error)
	ListIPDPIFlows(ctx context.Context, ip string, query Query) (DPIFlowPage, error)
	ListEvents(ctx context.Context, query Query) (EventPage, error)
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
