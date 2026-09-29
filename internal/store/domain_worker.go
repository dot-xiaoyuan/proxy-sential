package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
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
		go func() { defer close(s.domainDone); s.runDomainWorker(ctx) }()
	})
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

func (s *DBStore) runDomainWorker(parent context.Context) {
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
		case batch := <-s.domainQueue:
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
				err = s.processDomainBatch(ctx, batch)
				cancel()
				if err == nil {
					break
				}
				timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
				select {
				case <-timer.C:
				case <-parent.Done():
					timer.Stop()
					return
				}
			}
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

func (s *DBStore) processDomainBatch(ctx context.Context, batch domainBatch) error {
	// Materialize new DHCP observations before attributing application signals.
	devices := []normalized.Event{}
	for _, e := range batch.events {
		if e.Type == "device" && stringFromMap(e.Subject, "mac") != "" {
			devices = append(devices, e)
		}
	}
	if len(devices) > 0 {
		if err := s.pg.WriteIdentityEvents(ctx, devices); err != nil {
			return err
		}
	}
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
		if err := s.pg.WriteIdentityEvents(ctx, software); err != nil {
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
