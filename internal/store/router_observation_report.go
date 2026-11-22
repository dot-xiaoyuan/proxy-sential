package store

import (
	"context"
	"errors"
	"time"
)

type RouterObservationReport struct {
	AsOf      time.Time `json:"as_of"`
	Candidate int64     `json:"candidate"`
	Likely    int64     `json:"likely"`
	Confirmed int64     `json:"confirmed"`
}

func (s *DBStore) GetRouterObservationReport(ctx context.Context) (RouterObservationReport, error) {
	if s == nil || s.pg == nil {
		return RouterObservationReport{}, errors.New("router observation store unavailable")
	}
	return s.pg.GetRouterObservationReport(ctx)
}

func (s *PostgresStore) GetRouterObservationReport(ctx context.Context) (RouterObservationReport, error) {
	where, args, err := routerWhere(RouterQuery{Role: "router", IncludeCandidates: true})
	if err != nil {
		return RouterObservationReport{}, err
	}
	// Pick the same winner as the unfiltered router list before counting by
	// status. Counting each status separately can count one device twice.
	var report RouterObservationReport
	err = s.db.QueryRowContext(ctx, `SELECT now(),
 count(*) FILTER(WHERE status='candidate'),count(*) FILTER(WHERE status='likely'),
 count(*) FILTER(WHERE status='confirmed')
 FROM (
   SELECT DISTINCT ON (device_key) status FROM router_assessments `+where+`
   ORDER BY device_key,status_rank DESC,confidence DESC,(endpoint_id<>'') DESC,last_seen DESC,assessment_id
 ) current_routers`, args...).Scan(&report.AsOf, &report.Candidate, &report.Likely, &report.Confirmed)
	return report, err
}
