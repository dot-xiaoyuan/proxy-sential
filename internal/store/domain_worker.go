package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

type domainBatch struct {
	enqueuedAt time.Time
	events     []normalized.Event
	library    *fingerprint.Library
}

func (s *DBStore) StartDomainRecognition() {
	if os.Getenv("PROXY_SENTINEL_DOMAIN_RECOGNITION_DISABLED") == "true" {
		return
	}
	if s.pg == nil || s.ch == nil {
		return
	}
	s.domainOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		s.domainCancel = cancel
		s.domainDone = make(chan struct{})
		s.domainQueue = make(chan domainBatch, 32)
		workers := domainWorkerCount()
		go func() {
			var group sync.WaitGroup
			// 维护任务（对账与设备名重试）只跑一份，队列消费可以多份。
			group.Add(1)
			go func() { defer group.Done(); s.runDomainMaintenance(ctx) }()
			for index := 0; index < workers; index++ {
				group.Add(1)
				go func() { defer group.Done(); s.runDomainQueueWorker(ctx) }()
			}
			group.Wait()
			close(s.domainDone)
		}()
	})
}

// domainWorkerCount 决定域名识别队列的并发度。
//
// 现场设备事件约 1,700 条/秒，单个 worker 只能完成约 20% 的批次（10 分钟 155 批里丢弃 121 批），
// 其余由对账窗口补齐。身份写入本身由事务级 advisory lock 串行，多 worker 主要让域名处理、
// ClickHouse 观测写入与锁等待彼此重叠。默认 1 保持原行为。
func domainWorkerCount() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_DOMAIN_WORKERS")))
	if err != nil || n < 1 || n > 16 {
		return 1
	}
	return n
}
func (s *DBStore) enqueueDomainEvents(events []normalized.Event) {
	if os.Getenv("PROXY_SENTINEL_DOMAIN_RECOGNITION_DISABLED") == "true" {
		return
	}
	if s.pg == nil || s.ch == nil {
		return
	}
	filtered := make([]normalized.Event, 0)
	for _, e := range events {
		if e.Type == "device" {
			filtered = append(filtered, e)
			continue
		}
		if _, ok := ExtractDomainObservation(e); ok {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == 0 {
		return
	}
	s.StartDomainRecognition()
	// Normalized events are already durable in ClickHouse. Overflow is repaired
	// by the periodic ledger reconciliation, never by blocking packet ingestion.
	select {
	case s.domainQueue <- domainBatch{events: filtered, library: fingerprint.Default(), enqueuedAt: time.Now()}:
	default:
		log.Print("domain recognition queue full; durable events will be reconciled")
	}
}

func (s *DBStore) runDomainMaintenance(parent context.Context) {
	initial := time.NewTimer(0)
	defer initial.Stop()
	nameTicker := time.NewTicker(15 * time.Second)
	defer nameTicker.Stop()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-parent.Done():
			return
		case <-initial.C:
			ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
			err := s.reconcileDomainWindow(ctx)
			cancel()
			s.recordDomainError(err)
		case <-nameTicker.C:
			ctx, cancel := context.WithTimeout(parent, 10*time.Second)
			err := s.pg.RetryDeviceNames(ctx, nil)
			cancel()
			s.recordDomainError(err)
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
			err := s.reconcileDomainWindow(ctx)
			cancel()
			s.recordDomainError(err)
		}
	}
}

// runDomainQueueWorker 消费域名识别队列。多个 worker 共享同一队列，身份写入由
// advisory lock 串行，其余工作（域名处理、ClickHouse 观测写入）可以并行重叠。
func (s *DBStore) runDomainQueueWorker(parent context.Context) {
	for {
		select {
		case <-parent.Done():
			return
		case batch := <-s.domainQueue:
			// 单次尝试即放弃：事件已持久在 ClickHouse，失败批次由每 5 分钟的对账窗口补做。
			// 原先 3 次重试 × 2 分钟预算会把 worker 钉在同一个批次上：现场实测 10 分钟内
			// 42 次失败、只完成 1 个批次、同时丢弃 168 个新批次（覆盖率降到约 2%）。
			ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
			err := s.processDomainBatch(ctx, batch)
			cancel()
			s.recordDomainError(err)
		}
	}
}

// writeIdentityEventsChunked 把一批设备/软件事件切成有界事务写入。
//
// 身份写入全部串行在同一个事务级 advisory lock 上（见 writeIdentityEventsTx 的说明），
// 因此 ingest 的整批设备事件（可达数千条）会独占该锁上百秒：现场实测
// INSERT INTO endpoint_entities 等锁 48–53 秒，identity_ip_mac_history 自身单批插入跑了
// 100 秒以上，身份车道与设备实体写入被整条饿死。按身份车道相同的批大小分块后，单次持锁
// 降到数百行，其它写入可以在块与块之间插入。
func (s *DBStore) writeIdentityEventsChunked(ctx context.Context, events []normalized.Event) error {
	return writeInChunks(events, identitySignalBatchSize, func(chunk []normalized.Event) error {
		return s.pg.WriteIdentityEvents(ctx, chunk)
	})
}

// writeInChunks 按大小切分并顺序写出，任一块失败立即返回该错误。
func writeInChunks(events []normalized.Event, chunk int, write func([]normalized.Event) error) error {
	if chunk < 1 {
		chunk = 1
	}
	for start := 0; start < len(events); start += chunk {
		end := start + chunk
		if end > len(events) {
			end = len(events)
		}
		if err := write(events[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (s *DBStore) processDomainBatch(ctx context.Context, batch domainBatch) error {
	began := time.Now()
	deviceCount := 0
	// Materialize new DHCP observations before attributing application signals.
	devices := []normalized.Event{}
	for _, e := range batch.events {
		if e.Type == "device" && stringFromMap(e.Subject, "mac") != "" {
			devices = append(devices, e)
		}
	}
	if len(devices) > 0 {
		if err := s.writeIdentityEventsChunked(ctx, devices); err != nil {
			return err
		}
	}
	deviceCount = len(devices)
	identityPhase := time.Since(began)
	// Software announcements without a MAC may use a unique live DHCP lease.
	// Discovery queries are deliberately excluded: the queried name may be another device.
	software := []normalized.Event{}
	for _, e := range batch.events {
		if e.Type != "device" || stringFromMap(e.Payload, "origin") != "software" || stringFromMap(e.Subject, "mac") != "" {
			continue
		}
		owner, found, err := s.pg.ResolveDeviceAt(ctx, DomainObservation{IP: stringFromMap(e.Subject, "ip"), Timestamp: e.Timestamp, SensorID: stringFromMap(e.Observer, "sensor_id"), CampusID: stringFromMap(e.Subject, "campus_id")})
		if err != nil {
			return err
		}
		if !found || owner.Conflict {
			continue
		}
		copied := make(map[string]any, len(e.Subject)+1)
		for k, v := range e.Subject {
			copied[k] = v
		}
		copied["mac"] = strings.TrimPrefix(owner.EndpointID, "mac:")
		e.Subject = copied
		software = append(software, e)
	}
	if len(software) > 0 {
		if err := s.writeIdentityEventsChunked(ctx, software); err != nil {
			return err
		}
	}
	// Protocol self-report such as HTTP Server headers and TLS certificate
	// fields identifies a device but arrives without a link-layer address.
	// Attribute it through the same unique-lease rule as software
	// announcements. Derived events stay inside the device profile path and are
	// never written back to ClickHouse evidence or risk scoring.
	protocol, err := s.pg.protocolDeviceEvents(ctx, batch.events)
	if err != nil {
		return err
	}
	if len(protocol) > 0 {
		if err := s.pg.WriteProtocolDeviceEvents(ctx, protocol); err != nil {
			return err
		}
	}
	if err := s.pg.processDeviceNamesReceived(ctx, batch.events, batch.enqueuedAt); err != nil {
		return err
	}
	for _, event := range batch.events {
		if stringFromMap(event.Payload, "origin") == "dhcp" {
			if err := s.pg.RetryDeviceNames(ctx, batch.events); err != nil {
				return err
			}
			break
		}
	}
	libraries := []*fingerprint.Library{batch.library}
	active, _, err := s.pg.activeDomainVersion(ctx)
	if err != nil {
		return err
	}
	if active != "" && active != batch.library.Version() {
		var rules []byte
		if err := s.pg.db.QueryRowContext(ctx, `SELECT rules FROM domain_rule_versions WHERE version=$1`, active).Scan(&rules); err != nil {
			return err
		}
		library, err := fingerprint.LoadDomainLibrary(active, rules)
		if err != nil {
			return err
		}
		libraries = append(libraries, library)
	}
	for _, library := range libraries {
		result, err := s.pg.ProcessDomainEvents(ctx, batch.events, library)
		if err != nil {
			return err
		}
		if err := s.ch.WriteDomainEcosystemObservations(ctx, result.Observations); err != nil {
			return err
		}
	}
	// 现场需要区分"身份物化"与"域名处理"各占多少：设备事件以约 2,000 条/秒流入，
	// 而这条路径只能写十几行/秒，先量出相位占比再决定优化方向。阈值避免刷屏。
	if total := time.Since(began); total > 20*time.Second {
		log.Printf("domain batch timing: events=%d devices=%d identity=%s total=%s", len(batch.events), deviceCount, identityPhase.Round(time.Millisecond), total.Round(time.Millisecond))
	}
	return nil
}

func (s *DBStore) reconcileDomainWindow(ctx context.Context) error {
	if os.Getenv("PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED") == "true" {
		return nil
	}
	library := fingerprint.Default()
	// Incremental cursor with a ten-minute overlap repairs retry/identity races.
	// A resumable daily sweep also catches late records within the seven-day window.
	for _, kind := range []string{"incremental", "daily"} {
		if err := s.reconcileDomainCursor(ctx, library, kind); err != nil {
			return err
		}
	}
	return nil
}
func (s *DBStore) reconcileDomainCursor(ctx context.Context, library *fingerprint.Library, kind string) error {
	conn, err := s.pg.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	lock := "domain-reconcile:" + s.pg.sensorID + ":" + library.Version() + ":" + kind
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, lock).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtext($1))`, lock)
	now := time.Now().UTC()
	since := now.Add(-fingerprint.BrandEvidenceWindow)
	_, err = s.pg.db.ExecContext(ctx, `INSERT INTO domain_reconcile_cursors(sensor_id,rule_version,kind,cursor_timestamp) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, s.pg.sensorID, library.Version(), kind, since)
	if err != nil {
		return err
	}
	var cursor time.Time
	var cursorID string
	var completed sql.NullTime
	err = s.pg.db.QueryRowContext(ctx, `SELECT cursor_timestamp,cursor_event_id,completed_at FROM domain_reconcile_cursors WHERE sensor_id=$1 AND rule_version=$2 AND kind=$3`, s.pg.sensorID, library.Version(), kind).Scan(&cursor, &cursorID, &completed)
	if err != nil {
		return err
	}
	if completed.Valid {
		if kind == "daily" {
			if now.Sub(completed.Time) < 24*time.Hour {
				return nil
			}
			cursor = since
			cursorID = ""
		} else {
			cursor = cursor.Add(-10 * time.Minute)
			cursorID = ""
		}
	}
	if cursor.Before(since) {
		cursor = since
		cursorID = ""
	}
	for {
		events, err := s.ch.ListDomainEventsAfter(ctx, s.pg.sensorID, since.Format(time.RFC3339Nano), cursor.Format(time.RFC3339Nano), cursorID, 10000)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			_, err = s.pg.db.ExecContext(ctx, `UPDATE domain_reconcile_cursors SET cursor_timestamp=$4,cursor_event_id=$5,completed_at=now() WHERE sensor_id=$1 AND rule_version=$2 AND kind=$3`, s.pg.sensorID, library.Version(), kind, cursor, cursorID)
			return err
		}
		if err := s.processDomainBatch(ctx, domainBatch{events: events, library: library}); err != nil {
			return err
		}
		last := events[len(events)-1]
		cursor, err = time.Parse(time.RFC3339Nano, last.Timestamp)
		if err != nil {
			return err
		}
		cursorID = last.EventID
		_, err = s.pg.db.ExecContext(ctx, `UPDATE domain_reconcile_cursors SET cursor_timestamp=$4,cursor_event_id=$5,completed_at=NULL WHERE sensor_id=$1 AND rule_version=$2 AND kind=$3`, s.pg.sensorID, library.Version(), kind, cursor, cursorID)
		if err != nil {
			return err
		}
	}
}

func (s *DBStore) recordDomainError(err error) {
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.pg.db.ExecContext(ctx, `UPDATE domain_recognition_state SET last_error='',updated_at=now() WHERE singleton AND last_error<>''`)
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	log.Printf("domain recognition failed; durable replay will retry: %v", err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.pg.db.ExecContext(ctx, `INSERT INTO domain_recognition_state(singleton,active_version,last_error) VALUES(true,$1,$2) ON CONFLICT(singleton) DO UPDATE SET last_error=EXCLUDED.last_error,updated_at=now()`, fingerprint.Default().Version(), err.Error())
}

func (s *DBStore) activateDomainVersion(ctx context.Context, version string) error {
	// A newer import owns pending_version; an older completing job cannot win.
	result, err := s.pg.db.ExecContext(ctx, `UPDATE domain_recognition_state SET active_version=$1,pending_version='',last_error='',updated_at=now() WHERE singleton AND pending_version=$1`, version)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("domain version %s was superseded", version)
	}
	return nil
}
