package controlplane

import (
	"context"
	"fmt"
	"io"
	"proxy-sentinel/internal/store"
	"strconv"
	"time"
)

func (s *Server) identityMetrics(ctx context.Context, w io.Writer) {
	backend, ok := s.reader.(store.IdentityReconciler)
	if !ok {
		return
	}
	sources, err := backend.IdentitySources(ctx, time.Now().UTC())
	if err == nil {
		sources, err = s.mergeManagedIdentitySources(ctx, sources, time.Now().UTC())
	}
	available := 1
	if err != nil {
		available = 0
	}
	fmt.Fprintf(w, "# TYPE proxy_sentinel_identity_reconciliation_available gauge\nproxy_sentinel_identity_reconciliation_available %d\n", available)
	if err != nil {
		return
	}
	writeIdentityMetrics(w, sources)
}
func writeIdentityMetrics(w io.Writer, sources []store.IdentitySourceStatus) {
	fmt.Fprintln(w, "# TYPE proxy_sentinel_identity_source_interrupted gauge\n# TYPE proxy_sentinel_identity_snapshot_age_seconds gauge\n# TYPE proxy_sentinel_identity_snapshot_sessions gauge")
	for _, source := range sources {
		labels := fmt.Sprintf("source=%s,sensor_id=%s,campus_id=%s,access_domain=%s", strconv.Quote(source.Source), strconv.Quote(source.SensorID), strconv.Quote(source.CampusID), strconv.Quote(source.AccessDomain))
		interrupted := 0
		if source.State != "healthy" {
			interrupted = 1
		}
		fmt.Fprintf(w, "proxy_sentinel_identity_source_interrupted{%s} %d\nproxy_sentinel_identity_snapshot_age_seconds{%s} %g\nproxy_sentinel_identity_snapshot_sessions{%s} %d\n", labels, interrupted, labels, source.AgeSeconds, labels, source.SessionCount)
	}
}
