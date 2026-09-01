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
	IncludeWeak bool
}

type Page struct {
	Limit      int     `json:"limit"`
	NextCursor *string `json:"next_cursor"`
	Total      int     `json:"total"`
}

type RiskPage struct {
	Items []risk.Snapshot
	Page  Page
}

type DevicePage struct {
	Items []IPDeviceInventory `json:"items"`
	Page  Page                `json:"page"`
}

type EndpointDevicePage struct {
	Items []EndpointDeviceInventory `json:"items"`
	Page  Page                      `json:"page"`
}

type EventPage struct {
	Items []normalized.Event
	Page  Page
}

type Run struct {
	RunID                  string           `json:"run_id"`
	StartedAt              string           `json:"started_at"`
	FinishedAt             string           `json:"finished_at"`
	SensorID               string           `json:"sensor_id"`
	PreviousOffset         int64            `json:"previous_offset"`
	NewOffset              int64            `json:"new_offset"`
	Truncated              bool             `json:"truncated"`
	Normalized             NormalizedCounts `json:"normalized"`
	ZeekNormalized         NormalizedCounts `json:"zeek_normalized"`
	ZeekStatus             string           `json:"zeek_status"`
	ZeekReason             string           `json:"zeek_reason"`
	ZeekPrevOffset         int64            `json:"zeek_previous_offset"`
	ZeekNewOffset          int64            `json:"zeek_new_offset"`
	ZeekTruncated          bool             `json:"zeek_truncated"`
	ZeekSoftwarePrevOffset int64            `json:"zeek_software_previous_offset"`
	ZeekSoftwareNewOffset  int64            `json:"zeek_software_new_offset"`
	ZeekSoftwareTruncated  bool             `json:"zeek_software_truncated"`
	EvidenceCount          int              `json:"evidence_count"`
	RiskCount              int              `json:"risk_count"`
	RiskListCount          int              `json:"risk_list_count"`
	RawRef                 map[string]any   `json:"raw_ref"`
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

type AuditAppender interface {
	AppendAuditLog(ctx context.Context, item AuditLog) error
}

type DeviceProfileBackfiller interface {
	RebuildDeviceProfiles(ctx context.Context, batchSize int) (int, error)
}

type IdentityEventIngester interface {
	IngestIdentityEvents(ctx context.Context, events []normalized.Event) error
}

type Label struct {
	LabelID     string   `json:"label_id"`
	TargetType  string   `json:"target_type"`
	TargetID    string   `json:"target_id"`
	Label       string   `json:"label"`
	Reason      string   `json:"reason"`
	EvidenceIDs []string `json:"evidence_ids"`
	CreatedBy   string   `json:"created_by"`
	CreatedAt   string   `json:"created_at"`
}

type EndpointRegistrationUpdate struct {
	EndpointID            string `json:"endpoint_id"`
	RegistrationStatus    string `json:"registration_status"`
	OwnerAccount          string `json:"owner_account,omitempty"`
	OwnerName             string `json:"owner_name,omitempty"`
	OwnerDepartment       string `json:"owner_department,omitempty"`
	AssetTag              string `json:"asset_tag,omitempty"`
	RegistrationNote      string `json:"registration_note,omitempty"`
	MergeStatus           string `json:"merge_status"`
	MergedIntoEndpointID  string `json:"merged_into_endpoint_id,omitempty"`
	SplitFromEndpointID   string `json:"split_from_endpoint_id,omitempty"`
	RegistrationUpdatedBy string `json:"registration_updated_by"`
	RegistrationUpdatedAt string `json:"registration_updated_at"`
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
	SensorID    string
	Window      string
	Limit       int
	Cursor      int
	Q           string
	View        string
	SampleLimit int
}

type ActivityOverview struct {
	SensorID           string              `json:"sensor_id"`
	Window             string              `json:"window"`
	EventCount         int                 `json:"event_count"`
	ActiveIPCount      int                 `json:"active_ip_count"`
	AccessObjectCount  int                 `json:"access_object_count"`
	ActiveRiskIPCount  int                 `json:"active_risk_ip_count"`
	RiskLevelCounts    map[string]int      `json:"risk_level_counts"`
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

type ProxyReviewResponse struct {
	SensorID            string            `json:"sensor_id"`
	Window              string            `json:"window"`
	EventCount          int               `json:"event_count"`
	CaseCount           int               `json:"case_count"`
	AccountCount        int               `json:"account_count"`
	EndpointCount       int               `json:"endpoint_count"`
	DestinationCount    int               `json:"destination_count"`
	HighConfidenceCount int               `json:"high_confidence_count"`
	Items               []ProxyReviewCase `json:"items"`
	Page                Page              `json:"page"`
}

type ProxyReviewCase struct {
	CaseID             string           `json:"case_id"`
	IP                 string           `json:"ip"`
	AccountID          string           `json:"account_id,omitempty"`
	EndpointID         string           `json:"endpoint_id,omitempty"`
	AccessIDs          []string         `json:"access_ids"`
	Destinations       []ActivityCount  `json:"destinations"`
	DestinationIPs     []ActivityCount  `json:"destination_ips"`
	DestinationDomains []ActivityCount  `json:"destination_domains"`
	TLSFingerprints    []ActivityCount  `json:"tls_fingerprints"`
	Protocols          []ActivityCount  `json:"protocols"`
	RuleMatches        []ProxyRuleMatch `json:"rule_matches"`
	EventCount         int              `json:"event_count"`
	TLSCount           int              `json:"tls_count"`
	QUICCount          int              `json:"quic_count"`
	AlertCount         int              `json:"alert_count"`
	ConfidenceLevel    string           `json:"confidence_level"`
	FirstSeen          string           `json:"first_seen"`
	LastSeen           string           `json:"last_seen"`
	DurationSeconds    int64            `json:"duration_seconds"`
	EvidenceIDs        []string         `json:"evidence_ids"`
	RiskScore          int              `json:"risk_score"`
	RiskLevel          string           `json:"risk_level"`
	ReviewStatus       string           `json:"review_status"`
	ReviewReason       string           `json:"review_reason,omitempty"`
}

type ProxyRuleMatch struct {
	EventID   string `json:"event_id"`
	Signature string `json:"signature"`
	Category  string `json:"category,omitempty"`
	Action    string `json:"action,omitempty"`
	Severity  int    `json:"severity,omitempty"`
	Timestamp string `json:"timestamp"`
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
	BPSMbps      *float64 `json:"bps_mbps"`
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

type DeviceSignal struct {
	SignalID        string   `json:"signal_id"`
	IP              string   `json:"ip"`
	Source          string   `json:"source"`
	Kind            string   `json:"kind"`
	Value           string   `json:"value"`
	NormalizedValue string   `json:"normalized_value"`
	Strength        string   `json:"strength"`
	Confidence      float64  `json:"confidence"`
	Weight          int      `json:"weight"`
	EntityRole      string   `json:"entity_role,omitempty"`
	AccountID       string   `json:"account_id,omitempty"`
	EndpointID      string   `json:"endpoint_id,omitempty"`
	AccessID        string   `json:"access_id,omitempty"`
	FirstSeen       string   `json:"first_seen,omitempty"`
	LastSeen        string   `json:"last_seen,omitempty"`
	EventIDs        []string `json:"event_ids"`
	SeenCount       int      `json:"seen_count,omitempty"`
	EventIDsSample  []string `json:"event_ids_sample,omitempty"`
}

type ObservedDevice struct {
	DeviceID          string         `json:"device_id"`
	IP                string         `json:"ip"`
	Label             string         `json:"label"`
	Brand             string         `json:"brand"`
	Vendor            string         `json:"vendor"`
	OSFamily          string         `json:"os_family"`
	OSVersion         string         `json:"os_version"`
	DeviceType        string         `json:"device_type"`
	EntityRole        string         `json:"entity_role,omitempty"`
	AccountID         string         `json:"account_id,omitempty"`
	EndpointID        string         `json:"endpoint_id,omitempty"`
	AccessID          string         `json:"access_id,omitempty"`
	Model             string         `json:"model"`
	Confidence        float64        `json:"confidence"`
	SignalCount       int            `json:"signal_count"`
	StrongSignalCount int            `json:"strong_signal_count"`
	MediumSignalCount int            `json:"medium_signal_count"`
	WeakSignalCount   int            `json:"weak_signal_count"`
	Signals           []DeviceSignal `json:"signals"`
	Fingerprints      []string       `json:"fingerprints"`
	FirstSeen         string         `json:"first_seen,omitempty"`
	LastSeen          string         `json:"last_seen,omitempty"`
	Summary           string         `json:"summary"`
}

type DeviceConflict struct {
	ConflictID       string   `json:"conflict_id"`
	IP               string   `json:"ip"`
	Type             string   `json:"type"`
	Strength         string   `json:"strength"`
	Confidence       float64  `json:"confidence"`
	Summary          string   `json:"summary"`
	Samples          []string `json:"samples"`
	LastSeen         string   `json:"last_seen,omitempty"`
	RelatedDeviceIDs []string `json:"related_device_ids"`
}

type IPDeviceInventory struct {
	IP                   string           `json:"ip"`
	Window               string           `json:"window"`
	SuspectedDeviceCount int              `json:"suspected_device_count"`
	Confidence           float64          `json:"confidence"`
	Status               string           `json:"status"`
	Summary              string           `json:"summary"`
	Devices              []ObservedDevice `json:"devices"`
	Signals              []DeviceSignal   `json:"signals"`
	Conflicts            []DeviceConflict `json:"conflicts"`
	FirstSeen            string           `json:"first_seen,omitempty"`
	LastSeen             string           `json:"last_seen,omitempty"`
}

type EndpointDeviceInventory struct {
	EndpointID            string   `json:"endpoint_id"`
	PrimaryMAC            string   `json:"primary_mac,omitempty"`
	EntityRole            string   `json:"entity_role"`
	RegistrationStatus    string   `json:"registration_status"`
	OwnerAccount          string   `json:"owner_account,omitempty"`
	OwnerName             string   `json:"owner_name,omitempty"`
	OwnerDepartment       string   `json:"owner_department,omitempty"`
	AssetTag              string   `json:"asset_tag,omitempty"`
	MergeStatus           string   `json:"merge_status"`
	CurrentAccount        string   `json:"current_account,omitempty"`
	CurrentIP             string   `json:"current_ip,omitempty"`
	CurrentAccessID       string   `json:"current_access_id,omitempty"`
	Accounts              []string `json:"accounts"`
	IPs                   []string `json:"ips"`
	AccessIDs             []string `json:"access_ids"`
	FirstSeen             string   `json:"first_seen,omitempty"`
	LastSeen              string   `json:"last_seen,omitempty"`
	IdentityConfidence    float64  `json:"identity_confidence"`
	Vendor                string   `json:"vendor,omitempty"`
	Brand                 string   `json:"brand,omitempty"`
	Model                 string   `json:"model,omitempty"`
	DeviceType            string   `json:"device_type,omitempty"`
	OSFamily              string   `json:"os_family,omitempty"`
	RecognitionConfidence float64  `json:"recognition_confidence"`
	RecognitionSource     string   `json:"recognition_source,omitempty"`
	FingerprintVersion    string   `json:"fingerprint_version,omitempty"`
	RandomizedMAC         bool     `json:"randomized_mac"`
	RecognitionConflict   bool     `json:"recognition_conflict"`
	RecognitionEvidence   []string `json:"recognition_evidence,omitempty"`
	Summary               string   `json:"summary"`
}

type Reader interface {
	Overview(ctx context.Context) (Overview, error)
	ListRisks(ctx context.Context, query Query) (RiskPage, error)
	GetIPRisk(ctx context.Context, ip string) (risk.Snapshot, error)
	GetIPEvidence(ctx context.Context, ip string, limit int) ([]evidence.Evidence, error)
	GetIPActivity(ctx context.Context, ip string, limit int) (ActivityProfile, error)
	GetAccountIdentity(ctx context.Context, accountID string, query Query) (AccountIdentityProfile, bool, error)
	GetEndpointIdentity(ctx context.Context, endpointID string, query Query) (EndpointIdentityProfile, bool, error)
	ListEndpointDevices(ctx context.Context, query Query) (EndpointDevicePage, error)
	GetIPDeviceInventory(ctx context.Context, ip string, query ActivityQuery) (IPDeviceInventory, error)
	ListDeviceInventories(ctx context.Context, query Query) (DevicePage, error)
	GetDevice(ctx context.Context, deviceID string, query Query) (ObservedDevice, bool, error)
	ListDeviceSignals(ctx context.Context, query Query) ([]DeviceSignal, error)
	ListDeviceFingerprintConflicts(ctx context.Context, query Query) ([]DeviceConflict, error)
	GetActivityOverview(ctx context.Context, query ActivityQuery) (ActivityOverview, error)
	GetProxyReviews(ctx context.Context, query ActivityQuery) (ProxyReviewResponse, error)
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
	CreateLabel(ctx context.Context, label Label) (Label, error)
	UpdateEndpointRegistration(ctx context.Context, update EndpointRegistrationUpdate) (EndpointEntity, error)
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
	WriteDeviceState(ctx context.Context, run Run, events []normalized.Event, snapshots []risk.Snapshot) error
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

func (NoopWriter) WriteDeviceState(context.Context, Run, []normalized.Event, []risk.Snapshot) error {
	return nil
}
