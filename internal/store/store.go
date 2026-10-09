package store

import (
	"context"
	"fmt"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/fingerprint"
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
	View                  string
	DiagnosticStage       string
	DiagnosticType        string
	Level                 string
	Q                     string
	SensorID              string
	CampusID              string
	Department            string
	PersonType            string
	SSID                  string
	VLAN                  string
	AP                    string
	NASIP                 string
	Ecosystem             string
	Brand                 string
	OSFamily              string
	From                  string
	To                    string
	Window                string
	SrcIP                 string
	DstIP                 string
	Domain                string
	UserAgent             string
	Fingerprint           string
	Port                  int
	Proto                 string
	AppProtocol           string
	Limit                 int
	Cursor                int
	IncludeWeak           bool
	InventorySkipMetadata bool
	InventoryMetadataOnly bool
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
	Items      []EndpointDeviceInventory `json:"items"`
	Page       Page                      `json:"page"`
	Facets     DeviceFilterFacets        `json:"facets"`
	FacetsAsOf string                    `json:"facets_as_of,omitempty"`
}

// DeviceInventoryListItem is the bounded list projection used by the terminal
// inventory page. Complete association history and raw recognition evidence
// remain available from the endpoint detail APIs.
type DeviceInventoryListItem struct {
	Discovery            *discovery.Summary           `json:"discovery,omitempty"`
	RouterObservation    *evidence.RouterAssessment   `json:"router_observation,omitempty"`
	IPMatch              *DeviceIPMatch               `json:"ip_match,omitempty"`
	DeviceName           *DeviceName                  `json:"device_name,omitempty"`
	BrandReference       *fingerprint.BrandReference  `json:"brand_reference,omitempty"`
	BrandInference       *DeviceBrandInferenceSummary `json:"brand_inference,omitempty"`
	EndpointID           string                       `json:"endpoint_id"`
	PrimaryMAC           string                       `json:"primary_mac,omitempty"`
	OwnerAccount         string                       `json:"owner_account,omitempty"`
	OwnerName            string                       `json:"owner_name,omitempty"`
	CurrentAccount       string                       `json:"current_account,omitempty"`
	CurrentIP            string                       `json:"current_ip,omitempty"`
	CurrentAccessID      string                       `json:"current_access_id,omitempty"`
	LastSeen             string                       `json:"last_seen,omitempty"`
	Vendor               string                       `json:"vendor,omitempty"`
	Brand                string                       `json:"brand,omitempty"`
	Model                string                       `json:"model,omitempty"`
	DeviceType           string                       `json:"device_type,omitempty"`
	OSFamily             string                       `json:"os_family,omitempty"`
	VendorConfidence     float64                      `json:"vendor_confidence"`
	BrandConfidence      float64                      `json:"brand_confidence"`
	ModelConfidence      float64                      `json:"model_confidence"`
	DeviceTypeConfidence float64                      `json:"device_type_confidence"`
	OSFamilyConfidence   float64                      `json:"os_family_confidence"`
	RandomizedMAC        bool                         `json:"randomized_mac"`
	RecognitionConflict  bool                         `json:"recognition_conflict"`
}

type DeviceBrandInferenceSummary struct {
	Status     string  `json:"status"`
	Brand      string  `json:"brand,omitempty"`
	Confidence float64 `json:"confidence"`
}

type DeviceInventoryListPage struct {
	Items             []DeviceInventoryListItem `json:"items"`
	Page              Page                      `json:"page"`
	Facets            DeviceFilterFacets        `json:"facets"`
	AsOf              string                    `json:"as_of,omitempty"`
	ReadModelUpdating bool                      `json:"read_model_updating"`
}

func ProjectDeviceInventoryListItem(item EndpointDeviceInventory) DeviceInventoryListItem {
	projected := DeviceInventoryListItem{
		Discovery: item.Discovery, RouterObservation: item.RouterObservation, IPMatch: item.IPMatch,
		DeviceName: item.DeviceName, BrandReference: item.BrandReference,
		EndpointID: item.EndpointID, PrimaryMAC: item.PrimaryMAC, OwnerAccount: item.OwnerAccount,
		OwnerName: item.OwnerName, CurrentAccount: item.CurrentAccount, CurrentIP: item.CurrentIP,
		CurrentAccessID: item.CurrentAccessID, LastSeen: item.LastSeen, Vendor: item.Vendor,
		Brand: item.Brand, Model: item.Model, DeviceType: item.DeviceType, OSFamily: item.OSFamily,
		VendorConfidence: item.VendorConfidence, BrandConfidence: item.BrandConfidence,
		ModelConfidence: item.ModelConfidence, DeviceTypeConfidence: item.DeviceTypeConfidence,
		OSFamilyConfidence: item.OSFamilyConfidence, RandomizedMAC: item.RandomizedMAC,
		RecognitionConflict: item.RecognitionConflict,
	}
	if item.BrandInference != nil {
		projected.BrandInference = &DeviceBrandInferenceSummary{Status: item.BrandInference.Status, Brand: item.BrandInference.Brand, Confidence: item.BrandInference.Confidence}
	}
	return projected
}

type DeviceInventoryReader interface {
	ListDeviceInventory(context.Context, Query) (DeviceInventoryListPage, error)
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

type DeviceProfileBackfillProgress struct {
	Version   string `json:"version"`
	Status    string `json:"status"`
	Processed int    `json:"processed"`
	LastError string `json:"last_error,omitempty"`
}

// DeviceProfileVersionBackfiller persists progress per library version so a
// failed or interrupted offline-library import can safely resume by batch.
type DeviceProfileVersionBackfiller interface {
	RebuildDeviceProfilesVersion(ctx context.Context, version string, batchSize int, progress func(DeviceProfileBackfillProgress)) (DeviceProfileBackfillProgress, error)
}

type DomainEvidenceReader interface {
	ListEndpointDomainEvidence(ctx context.Context, endpointID string, limit int) ([]EndpointDomainEvidence, error)
}
type DomainEvidenceVersionBackfiller interface {
	RebuildDomainEvidenceVersion(ctx context.Context, version string, window time.Duration, batchSize int, progress func(DomainBackfillProgress)) (DomainBackfillProgress, error)
}

type IdentityEventIngester interface {
	IngestIdentityEvents(ctx context.Context, events []normalized.Event) error
}

type IdentityAttribution struct {
	SessionID      string `json:"session_id,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	EndpointID     string `json:"endpoint_id,omitempty"`
	PersonType     string `json:"person_type,omitempty"`
	Department     string `json:"department,omitempty"`
	CampusID       string `json:"campus_id,omitempty"`
	BuildingID     string `json:"building_id,omitempty"`
	NetworkZoneID  string `json:"network_zone_id,omitempty"`
	SSID           string `json:"ssid,omitempty"`
	VLAN           string `json:"vlan,omitempty"`
	AP             string `json:"ap,omitempty"`
	NASIP          string `json:"nas_ip,omitempty"`
	Conflict       bool   `json:"conflict"`
	ConflictReason string `json:"conflict_reason,omitempty"`
}

type IdentityAttributionResolver interface {
	ResolveIdentityAt(ctx context.Context, ip, at string) (IdentityAttribution, bool, error)
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
	OwnershipClass        string `json:"ownership_class"`
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
	CampusID    string
	AsOf        string
	Window      string
	Limit       int
	Cursor      int
	Q           string
	View        string
	SampleLimit int
}

type ActivityOverview struct {
	StatisticsAsOf     string              `json:"statistics_as_of,omitempty"`
	DataFreshness      *DataFreshness      `json:"data_freshness,omitempty"`
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

type DataFreshness struct {
	Status        string `json:"status"`
	AsOf          string `json:"as_of,omitempty"`
	LagSeconds    int64  `json:"lag_seconds"`
	AvailableFrom string `json:"available_from,omitempty"`
	Partial       bool   `json:"partial"`
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
	CaseID             string                     `json:"case_id"`
	IP                 string                     `json:"ip"`
	AccountID          string                     `json:"account_id,omitempty"`
	EndpointID         string                     `json:"endpoint_id,omitempty"`
	AccessIDs          []string                   `json:"access_ids"`
	Destinations       []ActivityCount            `json:"destinations"`
	DestinationIPs     []ActivityCount            `json:"destination_ips"`
	DestinationDomains []ActivityCount            `json:"destination_domains"`
	TLSFingerprints    []ActivityCount            `json:"tls_fingerprints"`
	Protocols          []ActivityCount            `json:"protocols"`
	RuleMatches        []ProxyRuleMatch           `json:"rule_matches"`
	EventCount         int                        `json:"event_count"`
	TLSCount           int                        `json:"tls_count"`
	QUICCount          int                        `json:"quic_count"`
	AlertCount         int                        `json:"alert_count"`
	ConfidenceLevel    string                     `json:"confidence_level"`
	FirstSeen          string                     `json:"first_seen"`
	LastSeen           string                     `json:"last_seen"`
	DurationSeconds    int64                      `json:"duration_seconds"`
	EvidenceIDs        []string                   `json:"evidence_ids"`
	RiskScore          int                        `json:"risk_score"`
	RiskLevel          string                     `json:"risk_level"`
	RiskConfidence     *float64                   `json:"risk_confidence,omitempty"`
	ReviewStatus       string                     `json:"review_status"`
	ReviewReason       string                     `json:"review_reason,omitempty"`
	SharedAccess       *SharedAccessCaseEvidence  `json:"shared_access,omitempty"`
	RouterObservation  *evidence.RouterAssessment `json:"router_observation,omitempty"`
}

// SharedAccessCaseEvidence records the exact strong anchor that caused a
// shared-access case. Generic traffic counters are deliberately kept out of
// this decision basis.
type SharedAccessCaseEvidence struct {
	ObservationID           string   `json:"observation_id"`
	GenerationID            string   `json:"generation_id"`
	Status                  string   `json:"status"`
	Confidence              int      `json:"confidence"`
	StrongAnchor            string   `json:"strong_anchor"`
	DeviceLowerBound        int      `json:"device_lower_bound"`
	CoverageState           string   `json:"coverage_state"`
	WindowStart             string   `json:"window_start"`
	WindowEnd               string   `json:"window_end"`
	SignalGroups            []string `json:"signal_groups"`
	Reasons                 []string `json:"reasons"`
	SourceEventIDs          []string `json:"source_event_ids"`
	AnchorIdentities        []string `json:"anchor_identities"`
	ReferenceDeviceCount24h int      `json:"reference_device_count_24h,omitempty"`
	RouterBrand             string   `json:"router_brand,omitempty"`
	RouterModel             string   `json:"router_model,omitempty"`
	RouterConfidence        int      `json:"router_confidence,omitempty"`
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
	StatisticsAsOf           string `json:"statistics_as_of,omitempty"`
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
	TopTargets   []string `json:"top_targets"`
}

type DPIFingerprintConflict struct {
	ID              string   `json:"id"`
	IP              string   `json:"ip"`
	ConflictType    string   `json:"conflict_type"`
	TypeLabel       string   `json:"type_label"`
	RiskLevel       string   `json:"risk_level"`
	Confidence      float64  `json:"confidence"`
	DeviceCount     int      `json:"device_count,omitempty"` // Deprecated: retained for response compatibility.
	SampleCount     int      `json:"sample_count"`
	Scope           string   `json:"scope"`
	SignalTypes     []string `json:"supporting_signal_types"`
	Assessment      string   `json:"assessment"`
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

type DeviceIPMatch struct {
	IP         string `json:"ip"`
	Source     string `json:"source"`
	MatchedAt  string `json:"matched_at"`
	IsRecentIP bool   `json:"is_recent_ip"`
}

type EndpointDeviceInventory struct {
	Discovery         *discovery.Summary         `json:"discovery,omitempty"`
	RouterObservation *evidence.RouterAssessment `json:"router_observation,omitempty"`
	IPMatch           *DeviceIPMatch             `json:"ip_match,omitempty"`
	DeviceName        *DeviceName                `json:"device_name,omitempty"`
	// Shared recognition snapshot; never serialized or used for identity fields.
	domainEvidence []fingerprint.DomainEvidence

	BrandReference         *fingerprint.BrandReference `json:"brand_reference,omitempty"`
	BrandInference         *fingerprint.BrandInference `json:"brand_inference,omitempty"`
	EndpointID             string                      `json:"endpoint_id"`
	PrimaryMAC             string                      `json:"primary_mac,omitempty"`
	EntityRole             string                      `json:"entity_role"`
	RegistrationStatus     string                      `json:"registration_status"`
	OwnerAccount           string                      `json:"owner_account,omitempty"`
	OwnerName              string                      `json:"owner_name,omitempty"`
	OwnerDepartment        string                      `json:"owner_department,omitempty"`
	AssetTag               string                      `json:"asset_tag,omitempty"`
	OwnershipClass         string                      `json:"ownership_class"`
	MergeStatus            string                      `json:"merge_status"`
	CurrentAccount         string                      `json:"current_account,omitempty"`
	CurrentIP              string                      `json:"current_ip,omitempty"` // Most recently observed address; does not imply online status.
	CurrentAccessID        string                      `json:"current_access_id,omitempty"`
	Accounts               []string                    `json:"accounts"`
	IPs                    []string                    `json:"ips"`
	AccessIDs              []string                    `json:"access_ids"`
	FirstSeen              string                      `json:"first_seen,omitempty"`
	LastSeen               string                      `json:"last_seen,omitempty"`
	IdentityConfidence     float64                     `json:"identity_confidence"`
	Vendor                 string                      `json:"vendor,omitempty"`
	Brand                  string                      `json:"brand,omitempty"`
	Model                  string                      `json:"model,omitempty"`
	DeviceType             string                      `json:"device_type,omitempty"`
	OSFamily               string                      `json:"os_family,omitempty"`
	RecognitionConfidence  float64                     `json:"recognition_confidence"`
	VendorConfidence       float64                     `json:"vendor_confidence"`
	BrandConfidence        float64                     `json:"brand_confidence"`
	ModelConfidence        float64                     `json:"model_confidence"`
	DeviceTypeConfidence   float64                     `json:"device_type_confidence"`
	OSFamilyConfidence     float64                     `json:"os_family_confidence"`
	RecognitionSource      string                      `json:"recognition_source,omitempty"`
	FingerprintVersion     string                      `json:"fingerprint_version,omitempty"`
	RandomizedMAC          bool                        `json:"randomized_mac"`
	RecognitionConflict    bool                        `json:"recognition_conflict"`
	RecognitionEvidence    []string                    `json:"recognition_evidence,omitempty"`
	EcosystemHint          string                      `json:"ecosystem_hint,omitempty"`
	EcosystemConfidence    float64                     `json:"ecosystem_confidence"`
	EcosystemConflict      bool                        `json:"ecosystem_conflict"`
	EcosystemEvidenceCount int                         `json:"ecosystem_evidence_count"`
	Summary                string                      `json:"summary"`
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
	Mode           Mode
	ShadowDir      string
	SensorID       string
	CollectorKind  string
	CollectorVer   string
	InterfaceName  string
	PostgresDSN    string
	ClickHouseDSN  string
	RequestTimeout time.Duration
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
