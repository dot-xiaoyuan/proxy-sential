package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

type DBStore struct {
	pg           *PostgresStore
	ch           *ClickHouseStore
	storageMode  Mode
	domainOnce   sync.Once
	domainQueue  chan domainBatch
	domainCancel context.CancelFunc
	domainDone   chan struct{}
}

func (s *DBStore) Health(ctx context.Context) error {
	if err := s.pg.Health(ctx); err != nil {
		return fmt.Errorf("PostgreSQL: %w", err)
	}
	if err := s.ch.Health(ctx); err != nil {
		return fmt.Errorf("ClickHouse: %w", err)
	}
	return nil
}

func NewDBStore(opts Options) (*DBStore, error) {
	pg, err := NewPostgresStore(PostgresOptions{
		DSN:           opts.PostgresDSN,
		SensorID:      opts.SensorID,
		CollectorKind: opts.CollectorKind,
		CollectorVer:  opts.CollectorVer,
		InterfaceName: opts.InterfaceName,
	})
	if err != nil {
		return nil, err
	}
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: opts.ClickHouseDSN, RequestTimeout: opts.RequestTimeout})
	if err != nil {
		return nil, err
	}
	mode := opts.Mode
	if mode == "" {
		mode = ModeDB
	}
	return &DBStore{pg: pg, ch: ch, storageMode: mode}, nil
}

func (s *DBStore) Overview(ctx context.Context) (Overview, error) {
	overview, err := s.pg.Overview(ctx)
	if err != nil {
		return Overview{}, err
	}
	eventTypes, err := s.ch.ListIngestEventTypes(ctx)
	if err == nil {
		events := 0
		for _, item := range eventTypes {
			events += item.Count
		}
		if overview.Throughput == nil {
			overview.Throughput = map[string]int{}
		}
		if events > 0 {
			overview.Throughput["events"] = events
		}
	}
	return overview, nil
}

func (s *DBStore) ListRisks(ctx context.Context, query Query) (RiskPage, error) {
	return s.pg.ListRisks(ctx, query)
}

func (s *DBStore) GetIPRisk(ctx context.Context, ip string) (risk.Snapshot, error) {
	return s.pg.GetIPRisk(ctx, ip)
}

func (s *DBStore) ListLabels(ctx context.Context, limit int) ([]Label, error) {
	return s.pg.ListLabels(ctx, limit)
}

func (s *DBStore) GetIPEvidence(ctx context.Context, ip string, limit int) ([]evidence.Evidence, error) {
	return s.pg.GetIPEvidence(ctx, ip, limit)
}

func (s *DBStore) GetIPActivity(ctx context.Context, ip string, limit int) (ActivityProfile, error) {
	return s.ch.GetIPActivity(ctx, ip, limit)
}

func (s *DBStore) GetAccountIdentity(ctx context.Context, accountID string, query Query) (AccountIdentityProfile, bool, error) {
	return s.pg.GetAccountIdentity(ctx, accountID, query)
}

func (s *DBStore) GetEndpointIdentity(ctx context.Context, endpointID string, query Query) (EndpointIdentityProfile, bool, error) {
	return s.pg.GetEndpointIdentity(ctx, endpointID, query)
}

func (s *DBStore) ListEndpointDevices(ctx context.Context, query Query) (EndpointDevicePage, error) {
	return s.pg.ListEndpointDevices(ctx, query)
}

func (s *DBStore) ListDeviceInventory(ctx context.Context, query Query) (DeviceInventoryListPage, error) {
	return s.pg.ListDeviceInventory(ctx, query)
}

func (s *DBStore) GetIPDeviceInventory(ctx context.Context, ip string, query ActivityQuery) (IPDeviceInventory, error) {
	return s.pg.GetIPDeviceInventory(ctx, ip, query)
}

func (s *DBStore) ListDeviceInventories(ctx context.Context, query Query) (DevicePage, error) {
	return s.pg.ListDeviceInventories(ctx, query)
}

func (s *DBStore) GetDevice(ctx context.Context, deviceID string, query Query) (ObservedDevice, bool, error) {
	return s.pg.GetDevice(ctx, deviceID, query)
}

func (s *DBStore) ListDeviceSignals(ctx context.Context, query Query) ([]DeviceSignal, error) {
	return s.pg.ListDeviceSignals(ctx, query)
}

func (s *DBStore) ListDeviceFingerprintConflicts(ctx context.Context, query Query) ([]DeviceConflict, error) {
	return s.pg.ListDeviceFingerprintConflicts(ctx, query)
}

func (s *DBStore) GetActivityOverview(ctx context.Context, query ActivityQuery) (ActivityOverview, error) {
	window, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return ActivityOverview{}, err
	}
	if query.SensorID == "" {
		query.SensorID = s.pg.sensorID
	}
	risks, err := s.pg.RiskSnapshotMap(ctx)
	if err != nil {
		return ActivityOverview{}, err
	}
	query.Window = window
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3")), "true") {
		freshness, freshnessErr := s.activityV3Freshness(ctx, duration, query.AsOf)
		if freshnessErr != nil {
			return ActivityOverview{}, freshnessErr
		}
		result, queryErr := s.ch.getActivityOverview(ctx, query, duration, risks, true)
		result.StatisticsAsOf = freshness.AsOf
		result.DataFreshness = &freshness
		return result, queryErr
	}
	if err := s.activityStatisticsReadModelHealth(ctx); err != nil {
		return ActivityOverview{}, err
	}
	var sourceAt time.Time
	if err := s.pg.db.QueryRowContext(ctx, `SELECT updated_at FROM activity_chart_read_model_cursor_v2 WHERE id=1`).Scan(&sourceAt); err != nil {
		return ActivityOverview{}, err
	}
	result, err := s.ch.getActivityOverview(ctx, query, duration, risks, true)
	result.StatisticsAsOf = sourceAt.UTC().Format(time.RFC3339Nano)
	return result, err
}

func (s *DBStore) activityV3Freshness(ctx context.Context, window time.Duration, rawAsOf string) (DataFreshness, error) {
	cutover, err := s.readActivityV3Cutover(ctx)
	if err != nil {
		return DataFreshness{}, err
	}
	asOf := time.Time{}
	var raw string
	if err = s.pg.db.QueryRowContext(ctx, `SELECT state->>'as_of' FROM read_model_runtime_state WHERE name='activity-v3-5m'`).Scan(&raw); err == nil && raw != "" {
		asOf, err = parseReadModelTime(raw)
		if err != nil {
			return DataFreshness{}, err
		}
	} else if err != nil && err != sql.ErrNoRows {
		return DataFreshness{}, err
	}
	now := time.Now().UTC()
	requestedTo := now
	if rawAsOf != "" {
		requestedTo, err = time.Parse(time.RFC3339Nano, rawAsOf)
		if err != nil {
			return DataFreshness{}, err
		}
	}
	lag := int64(0)
	status := "warming"
	if !asOf.IsZero() {
		lag = int64(now.Sub(asOf).Seconds())
		if lag < 0 {
			lag = 0
		}
		switch {
		case lag <= 60:
			status = "fresh"
		case lag <= 300:
			status = "delayed"
		default:
			status = "stale"
		}
	}
	asOfText := ""
	if !asOf.IsZero() {
		asOfText = asOf.UTC().Format(time.RFC3339Nano)
	}
	return DataFreshness{
		Status:        status,
		AsOf:          asOfText,
		LagSeconds:    lag,
		AvailableFrom: cutover.UTC().Format(time.RFC3339Nano),
		Partial:       requestedTo.Add(-window).Before(cutover),
	}, nil
}

func (s *DBStore) GetProxyReviews(ctx context.Context, query ActivityQuery) (ProxyReviewResponse, error) {
	window, duration, err := NormalizeActivityWindow(firstNonEmpty(query.Window, defaultProxyReviewWindow))
	if err != nil {
		return ProxyReviewResponse{}, err
	}
	// The background case synchronizer consumes the same rolling ten-minute
	// window as the risk materializer. Public review lists remain 24h/7d.
	if window != "10m" && window != "24h" && window != "7d" {
		return ProxyReviewResponse{}, fmt.Errorf("proxy review window must be one of 10m, 24h, 7d")
	}
	sensorID := firstNonEmpty(query.SensorID, s.pg.sensorID)
	limit := query.SampleLimit
	if limit <= 0 {
		limit = defaultProxyReviewLimit
	}
	events, err := s.ch.ListProxyReviewEvents(ctx, sensorID, duration, limit)
	if err != nil {
		return ProxyReviewResponse{}, err
	}
	riskPage, err := s.pg.ListRisks(ctx, Query{SensorID: sensorID, Limit: defaultProxyReviewLimit})
	if err != nil {
		return ProxyReviewResponse{}, err
	}
	return BuildProxyReviewResponse(sensorID, window, events, ProxyReviewRiskMap(riskPage.Items)), nil
}

func (s *DBStore) GetDPIOverview(ctx context.Context, query ActivityQuery) (DPIOverview, error) {
	window, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return DPIOverview{}, err
	}
	query.Window = window
	if query.SensorID == "" {
		query.SensorID = s.pg.sensorID
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3")), "true") {
		freshness, e := s.activityV3Freshness(ctx, duration, query.AsOf)
		if e != nil {
			return DPIOverview{}, e
		}
		result, e := s.ch.queryDPICoarseOverview(ctx, query)
		result.StatisticsAsOf = freshness.AsOf
		return result, e
	}
	if err = s.activityStatisticsReadModelHealth(ctx); err != nil {
		return DPIOverview{}, err
	}
	var sourceAt time.Time
	if err = s.pg.db.QueryRowContext(ctx, `SELECT updated_at FROM activity_chart_read_model_cursor_v2 WHERE id=1`).Scan(&sourceAt); err != nil {
		return DPIOverview{}, err
	}
	result, err := s.ch.queryDPICoarseOverview(ctx, query)
	result.StatisticsAsOf = sourceAt.UTC().Format(time.RFC3339Nano)
	return result, err
}

func (s *DBStore) ListDPITrends(ctx context.Context, query ActivityQuery) ([]DPITrendPoint, error) {
	risks, err := s.pg.RiskSnapshotMap(ctx)
	if err != nil {
		return nil, err
	}
	return s.ch.QueryDPITrends(ctx, query, risks)
}

func (s *DBStore) ListDPIProtocolFlows(ctx context.Context, query ActivityQuery) ([]DPIProtocolFlow, error) {
	return s.ch.QueryDPIProtocolFlows(ctx, query)
}

func (s *DBStore) ListDPIFingerprintConflicts(ctx context.Context, query ActivityQuery) ([]DPIFingerprintConflict, error) {
	risks, err := s.pg.RiskSnapshotMap(ctx)
	if err != nil {
		return nil, err
	}
	return s.ch.QueryDPIFingerprintConflicts(ctx, query, risks)
}

func (s *DBStore) ListDPIFlows(ctx context.Context, query Query) (DPIFlowPage, error) {
	return s.ch.ListDPIFlows(ctx, query)
}

func (s *DBStore) GetDPIFlow(ctx context.Context, flowID string) (DPIFlowDetail, bool, error) {
	event, ok, err := s.ch.GetEvent(ctx, flowID)
	if err != nil || !ok {
		return DPIFlowDetail{}, ok, err
	}
	ip := subjectIP(event)
	snapshot, err := s.pg.GetIPRisk(ctx, ip)
	if err != nil {
		return DPIFlowDetail{}, false, err
	}
	items, err := s.pg.GetIPEvidence(ctx, ip, 20)
	if err != nil {
		return DPIFlowDetail{}, false, err
	}
	return BuildDPIFlowDetail(event, snapshot, items), true, nil
}

func (s *DBStore) ListIPDPIFlows(ctx context.Context, ip string, query Query) (DPIFlowPage, error) {
	return s.ch.ListIPDPIFlows(ctx, ip, query)
}

func (s *DBStore) dpiEventSet(ctx context.Context, query ActivityQuery) (string, []normalized.Event, map[string]risk.Snapshot, string, error) {
	window, _, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return "", nil, nil, "", err
	}
	if query.SensorID == "" {
		query.SensorID = s.pg.sensorID
	}
	limit := query.Limit
	if limit <= 0 {
		limit = defaultDPIEventLimit
	}
	events, err := s.ch.ListEventSamples(ctx, Query{SensorID: query.SensorID, Window: window, Limit: limit})
	if err != nil {
		return "", nil, nil, "", err
	}
	risks, err := s.pg.RiskSnapshotMap(ctx)
	if err != nil {
		return "", nil, nil, "", err
	}
	return window, events, risks, query.SensorID, nil
}

func (s *DBStore) ListEventSamples(ctx context.Context, query Query) ([]normalized.Event, error) {
	return s.ch.ListEventSamples(ctx, query)
}

func (s *DBStore) ListEvents(ctx context.Context, query Query) (EventPage, error) {
	return s.ch.ListEvents(ctx, query)
}

func (s *DBStore) GetEvent(ctx context.Context, eventID string) (normalized.Event, bool, error) {
	return s.ch.GetEvent(ctx, eventID)
}

func (s *DBStore) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	return s.pg.ListRuns(ctx, limit)
}

func (s *DBStore) ListSensorRuns(ctx context.Context, sensorID string, limit int) ([]Run, error) {
	return s.pg.ListSensorRuns(ctx, sensorID, limit)
}

func (s *DBStore) ListRunsPage(ctx context.Context, query Query) ([]Run, Page, error) {
	return s.pg.ListRunsPage(ctx, query)
}

func (s *DBStore) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	return s.pg.ListAuditLogs(ctx, limit)
}

func (s *DBStore) ListAuditLogsPage(ctx context.Context, query Query) ([]AuditLog, Page, error) {
	return s.pg.ListAuditLogsPage(ctx, query)
}

func (s *DBStore) AppendAuditLog(ctx context.Context, item AuditLog) error {
	return s.pg.AppendAuditLog(ctx, item)
}

func (s *DBStore) RebuildDeviceProfiles(ctx context.Context, batchSize int) (int, error) {
	return s.pg.RebuildDeviceProfiles(ctx, batchSize)
}

func (s *DBStore) RebuildDeviceProfilesVersion(ctx context.Context, version string, batchSize int, progress func(DeviceProfileBackfillProgress)) (DeviceProfileBackfillProgress, error) {
	return s.pg.RebuildDeviceProfilesVersion(ctx, version, batchSize, progress)
}

func (s *DBStore) CreateLabel(ctx context.Context, label Label) (Label, error) {
	return s.pg.CreateLabel(ctx, label)
}

func (s *DBStore) UpdateEndpointRegistration(ctx context.Context, update EndpointRegistrationUpdate) (EndpointEntity, error) {
	return s.pg.UpdateEndpointRegistration(ctx, update)
}

func (s *DBStore) IngestStatus(ctx context.Context) (ingest.Status, error) {
	runs, err := s.pg.ListSensorRuns(ctx, s.pg.sensorID, 1)
	if err != nil {
		return ingest.Status{}, err
	}
	status := ingest.Status{
		SensorID:          s.pg.sensorID,
		Collector:         s.pg.collector(),
		StorageMode:       string(s.storageMode),
		Healthy:           len(runs) > 0,
		Severity:          "warning",
		Summary:           "no collector runs found",
		LastCounters:      map[string]int{"read": 0, "emitted": 0, "skipped": 0, "malformed": 0},
		LastEventTypeDist: map[string]int{},
	}
	if len(runs) == 0 {
		return status, nil
	}
	run := runs[0]
	status.LatestRunID = run.RunID
	status.LatestRunAt = run.FinishedAt
	status.LastCounters = map[string]int{
		"read":      run.Normalized.Read,
		"emitted":   run.Normalized.Emitted,
		"skipped":   run.Normalized.Skipped,
		"malformed": run.Normalized.Malformed,
	}
	eventTypes, _ := s.ch.ListSensorIngestEventTypes(ctx, s.pg.sensorID)
	status.LastEventTypeDist = map[string]int{}
	for _, item := range eventTypes {
		status.LastEventTypeDist[item.Type] = item.Count
	}
	status.Healthy = run.Normalized.Malformed == 0 && !run.Truncated
	status.Severity = "info"
	status.Summary = "collector and normalization pipeline are producing standard events"
	if run.Truncated {
		status.Severity = "warning"
		status.Summary = "input log was truncated or rotated during the latest run"
	} else if run.Normalized.Malformed > 0 {
		status.Severity = "warning"
		status.Summary = "latest run contains malformed input records"
	}
	return status, nil
}

func (s *DBStore) ListIngestDiagnostics(ctx context.Context, query Query) ([]ingest.Diagnostic, error) {
	return s.ch.ListIngestDiagnostics(ctx, query)
}

func (s *DBStore) ListIngestDiagnosticsPage(ctx context.Context, query Query, errorsOnly bool) ([]ingest.Diagnostic, Page, error) {
	return s.ch.ListIngestDiagnosticsPage(ctx, query, errorsOnly)
}

func (s *DBStore) ListIngestEventTypes(ctx context.Context) ([]ingest.EventTypeCount, error) {
	return s.ch.ListIngestEventTypes(ctx)
}

func (s *DBStore) ListIngestErrors(ctx context.Context, limit int) ([]ingest.Diagnostic, error) {
	return s.ch.ListIngestErrors(ctx, limit)
}

func (s *DBStore) WriteCollectorRun(ctx context.Context, run Run) error {
	return s.pg.WriteCollectorRun(ctx, run)
}

func (s *DBStore) WriteNormalizedEvents(ctx context.Context, events []normalized.Event) error {
	if err := s.ch.WriteNormalizedEvents(ctx, events); err != nil {
		return err
	}
	s.enqueueDomainEvents(events)
	return nil
}

func (s *DBStore) IngestIdentityEvents(ctx context.Context, events []normalized.Event) error {
	if err := s.ch.WriteNormalizedEvents(ctx, events); err != nil {
		return err
	}
	return s.pg.WriteIdentityEvents(ctx, events)
}

func (s *DBStore) ResolveIdentityAt(ctx context.Context, ip, at string) (IdentityAttribution, bool, error) {
	return s.pg.ResolveIdentityAt(ctx, ip, at)
}

func (s *DBStore) WriteIngestDiagnostics(ctx context.Context, diagnostics []ingest.Diagnostic) error {
	return s.ch.WriteIngestDiagnostics(ctx, diagnostics)
}

func (s *DBStore) WriteEvidence(ctx context.Context, items []evidence.Evidence) error {
	return s.pg.WriteEvidence(ctx, items)
}

func (s *DBStore) WriteRiskSnapshots(ctx context.Context, snapshots []risk.Snapshot) error {
	return s.pg.WriteRiskSnapshots(ctx, snapshots)
}

func (s *DBStore) ExpireRiskSnapshots(ctx context.Context, before time.Time) error {
	return s.pg.ExpireRiskSnapshots(ctx, before)
}

func (s *DBStore) WriteDeviceState(ctx context.Context, run Run, events []normalized.Event, snapshots []risk.Snapshot) error {
	if err := s.pg.WriteDeviceState(ctx, run, events, snapshots); err != nil {
		return err
	}
	s.enqueueDomainEvents(events)
	return nil
}

func (s *DBStore) ListEndpointDomainEvidence(ctx context.Context, endpointID string, limit int) ([]EndpointDomainEvidence, error) {
	return s.pg.ListEndpointDomainEvidence(ctx, endpointID, limit)
}

func (s *DBStore) RebuildDomainEvidenceVersion(ctx context.Context, version string, window time.Duration, batchSize int, progress func(DomainBackfillProgress)) (result DomainBackfillProgress, resultErr error) {
	if version == "" {
		return result, fmt.Errorf("domain rule version is required")
	}
	library := fingerprint.Default()
	if library.Version() != version {
		return result, fmt.Errorf("domain backfill version %s is not loaded", version)
	}

	if window <= 0 {
		window = 7 * 24 * time.Hour
	}
	if batchSize <= 0 || batchSize > MaxDomainBatchSize {
		batchSize = MaxDomainBatchSize
	}
	conn, err := s.pg.db.Conn(ctx)
	if err != nil {
		return result, err
	}
	defer conn.Close()
	lockName := "proxy-sentinel-domain-evidence-backfill"
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext($1))`, lockName); err != nil {
		return result, err
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtext($1))`, lockName)
	if fingerprint.Default().Version() != version {
		return result, fmt.Errorf("domain version %s was superseded", version)
	}
	if _, err := s.pg.db.ExecContext(ctx, `INSERT INTO domain_recognition_state(singleton,pending_version) VALUES(true,$1) ON CONFLICT(singleton) DO UPDATE SET pending_version=EXCLUDED.pending_version,updated_at=now()`, version); err != nil {
		return result, err
	}
	if _, err := s.pg.db.ExecContext(ctx, `INSERT INTO domain_rule_versions(version,rules) VALUES($1,$2) ON CONFLICT DO NOTHING`, version, library.DomainRulesJSON()); err != nil {
		return result, err
	}

	since := time.Now().UTC().Add(-window)
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO domain_evidence_backfill_jobs(version,status,cursor_timestamp,started_at,updated_at) VALUES($1,'pending',$2,now(),now()) ON CONFLICT(version) DO NOTHING`, version, since)
	if err != nil {
		return result, err
	}
	result, err = s.pg.loadDomainBackfillProgress(ctx, version)
	if err != nil {
		return result, err
	}
	if result.Status == "completed" {
		if err := s.activateDomainVersion(ctx, version); err != nil {
			return result, err
		}
		if progress != nil {
			progress(result)
		}
		return result, nil
	}
	_, err = s.pg.db.ExecContext(ctx, `UPDATE domain_evidence_backfill_jobs SET status='running',last_error=NULL,started_at=COALESCE(started_at,now()),finished_at=NULL,updated_at=now() WHERE version=$1`, version)
	if err != nil {
		return result, err
	}
	result.Status = "running"
	if progress != nil {
		progress(result)
	}
	defer func() {
		if resultErr != nil {
			s.pg.saveDomainBackfillFailure(version, resultErr)
			result.Status = "failed"
			result.LastError = resultErr.Error()
			if progress != nil {
				progress(result)
			}
		}
	}()
	for library.DomainRuleCount() > 0 {
		if fingerprint.Default().Version() != version {
			return result, fmt.Errorf("domain version %s was superseded", version)
		}
		events, queryErr := s.ch.ListDomainEventsAfter(ctx, s.pg.sensorID, since.Format(time.RFC3339Nano), result.CursorTimestamp, result.CursorEventID, batchSize)
		if queryErr != nil {
			return result, queryErr
		}
		if len(events) == 0 {
			break
		}
		batchResult, processErr := s.pg.ProcessDomainEvents(ctx, events, library)
		if processErr != nil {
			return result, processErr
		}
		if writeErr := s.ch.WriteDomainEcosystemObservations(ctx, batchResult.Observations); writeErr != nil {
			return result, writeErr
		}
		last := events[len(events)-1]
		result.Processed += batchResult.Processed
		result.Matched += batchResult.Matched
		result.Attributed += batchResult.Attributed
		result.CursorTimestamp = last.Timestamp
		result.CursorEventID = last.EventID
		_, updateErr := s.pg.db.ExecContext(ctx, `UPDATE domain_evidence_backfill_jobs SET cursor_timestamp=$2,cursor_event_id=$3,processed=$4,attributed=$5,matched=$6,updated_at=now() WHERE version=$1`, version, last.Timestamp, last.EventID, result.Processed, result.Attributed, result.Matched)
		if updateErr != nil {
			return result, updateErr
		}
		if progress != nil {
			progress(result)
		}
		if len(events) < batchSize {
			break
		}
	}
	_, err = s.pg.db.ExecContext(ctx, `UPDATE domain_evidence_backfill_jobs SET status='completed',last_error=NULL,finished_at=now(),updated_at=now() WHERE version=$1`, version)
	if err != nil {
		return result, err
	}
	result.Status = "completed"
	if err := s.activateDomainVersion(ctx, version); err != nil {
		return result, err
	}
	if progress != nil {
		progress(result)
	}
	return result, nil
}

func dbRequired(name string, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required for db storage mode", name)
	}
	return nil
}
