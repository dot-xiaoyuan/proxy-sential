package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"
)

// Traffic observations are IP-scoped source events, not device identity facts.
// This reader reuses the existing narrow index and adds no storage or writer.
type IPTrafficObservationQuery struct {
	SensorID, IP, SourceOwner, Protocol, Cursor string
	From, To                                    time.Time
	Limit                                       int
}

func (q IPTrafficObservationQuery) Validate() error {
	ip, err := netip.ParseAddr(q.IP)
	if err != nil || ip.Zone() != "" || q.SensorID == "" || len(q.SensorID) > 256 ||
		(q.SourceOwner != "handshake-sidecar" && q.SourceOwner != "packet-sidecar") ||
		(q.Protocol != "" && !trafficObservationProtocol(q.Protocol)) ||
		q.From.IsZero() || !q.To.After(q.From) || q.To.Sub(q.From) > 15*time.Minute ||
		q.Limit < 1 || q.Limit > 100 || len(q.Cursor) > 1024 {
		return ErrInvalidStreamEventIndexQuery
	}
	return nil
}

func trafficObservationProtocol(protocol string) bool {
	return protocol == "handshake" || protocol == "ttl" || protocol == "hop_limit"
}

type IPTrafficObservationSource struct {
	Epoch    string    `json:"epoch"`
	ScopeID  string    `json:"scope_id"`
	CutoffAt time.Time `json:"cutoff_at"`
	State    string    `json:"state"`
}

type IPTrafficObservationPage struct {
	StreamEventIndexPage
	IP          string                      `json:"ip"`
	SourceOwner string                      `json:"source_owner"`
	Status      string                      `json:"status"`
	From        time.Time                   `json:"from"`
	To          time.Time                   `json:"to"`
	QueriedAt   time.Time                   `json:"queried_at"`
	Source      *IPTrafficObservationSource `json:"source,omitempty"`
}

func (s *DBStore) ListIPTrafficObservations(ctx context.Context, q IPTrafficObservationQuery) (IPTrafficObservationPage, error) {
	if err := q.Validate(); err != nil {
		return IPTrafficObservationPage{}, err
	}
	if s == nil || s.pg == nil || s.pg.db == nil {
		return IPTrafficObservationPage{}, errors.New("traffic source metadata unavailable")
	}
	ip, _ := netip.ParseAddr(q.IP)
	page := IPTrafficObservationPage{StreamEventIndexPage: StreamEventIndexPage{Items: []StreamEventIndexItem{}},
		IP: ip.Unmap().String(), SourceOwner: q.SourceOwner, From: q.From.UTC(), To: q.To.UTC(), Status: "source_unavailable"}
	var source IPTrafficObservationSource
	// At most one active owner generation exists per sensor. Paused/closed
	// file-source state is returned explicitly; it does not prove live capture.
	err := s.pg.db.QueryRowContext(ctx, `SELECT s.epoch,s.scope_id,s.source_cutoff_at,c.state
 FROM stream_shared_source_cutovers s
 JOIN stream_source_cutovers c USING(epoch,source_kind,source_path)
 WHERE s.sensor_id=$1 AND s.source_owner=$2 AND s.state='active' AND c.sensor_id=s.sensor_id`, q.SensorID, q.SourceOwner).
		Scan(&source.Epoch, &source.ScopeID, &source.CutoffAt, &source.State)
	if errors.Is(err, sql.ErrNoRows) {
		page.QueriedAt = time.Now().UTC()
		return page, nil
	}
	if err != nil {
		return IPTrafficObservationPage{}, err
	}
	if source.Epoch == "" || source.ScopeID == "" || source.CutoffAt.IsZero() {
		return IPTrafficObservationPage{}, errors.New("traffic source metadata incomplete")
	}
	source.CutoffAt = source.CutoffAt.UTC()
	page.Source = &source
	if !q.To.After(source.CutoffAt) {
		page.Status = "before_cutover"
		page.QueriedAt = time.Now().UTC()
		return page, nil
	}
	if page.From.Before(source.CutoffAt) {
		page.From = source.CutoffAt
	}
	if s.ch == nil {
		return IPTrafficObservationPage{}, errors.New("traffic event index unavailable")
	}
	indexed, err := s.ch.ListStreamEventIndex(ctx, StreamEventIndexQuery{ScopeID: source.ScopeID, Protocol: q.Protocol,
		SensorID: q.SensorID, SubjectIP: page.IP, Epoch: source.Epoch, ObservationOnly: true,
		From: page.From, To: page.To, Limit: q.Limit, Cursor: q.Cursor})
	if err != nil {
		return IPTrafficObservationPage{}, err
	}
	page.StreamEventIndexPage = indexed
	page.Status = "ready"
	page.QueriedAt = time.Now().UTC()
	return page, nil
}
