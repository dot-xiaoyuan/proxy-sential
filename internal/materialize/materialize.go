package materialize

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
)

// Store is the deliberately small materializer surface. Keeping it separate
// from the ingest worker prevents risk aggregation from entering the hot path.
type Store interface {
	ListEventSamples(context.Context, store.Query) ([]normalized.Event, error)
	WriteEvidence(context.Context, []evidence.Evidence) error
	WriteRiskSnapshots(context.Context, []risk.Snapshot) error
	ExpireRiskSnapshots(context.Context, time.Time) error
	WriteCollectorRun(context.Context, store.Run) error
}

type Options struct {
	SharedAccess bool
	SensorID     string
	Window       time.Duration
	Limit        int
}

type Result struct {
	Events            int
	Evidence          int
	Snapshots         int
	RouterEvidence    int
	RouterAssessments int
	StartedAt         time.Time
	CompletedAt       time.Time
}

func RunOnce(ctx context.Context, backend Store, opts Options) (Result, error) {
	if opts.Window <= 0 {
		opts.Window = 10 * time.Minute
	}
	if opts.Limit <= 0 {
		opts.Limit = 200000
	}
	result := Result{StartedAt: time.Now().UTC()}
	windowText, err := queryWindow(opts.Window)
	if err != nil {
		return result, err
	}
	events, err := backend.ListEventSamples(ctx, store.Query{SensorID: opts.SensorID, Window: windowText, Limit: opts.Limit, From: result.StartedAt.Add(-opts.Window).Format(time.RFC3339Nano), To: result.StartedAt.Format(time.RFC3339Nano)})
	if err != nil {
		return result, fmt.Errorf("query rolling event window: %w", err)
	}
	result.Events = len(events)
	var lines bytes.Buffer
	encoder := json.NewEncoder(&lines)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return result, err
		}
	}
	evidenceResult, err := evidence.Analyze(&lines, evidence.Options{Window: opts.Window})
	if err != nil {
		return result, fmt.Errorf("aggregate evidence: %w", err)
	}
	result.Evidence = len(evidenceResult.Evidence)
	if opts.SharedAccess {
		var windows []sharedaccess.Window
		if identityReader, ok := backend.(store.PolicyIdentityReader); ok {
			sessions, identityErr := identityReader.ListPolicySessions(ctx, result.StartedAt)
			if identityErr != nil {
				return result, fmt.Errorf("query identity generations: %w", identityErr)
			}
			windows = evidence.SharedWindowsBySession(events, sessions, result.StartedAt.Add(-opts.Window), result.StartedAt, len(events) < opts.Limit)
		} else {
			return result, fmt.Errorf("shared materialization requires an identity generation reader")
		}

		for _, window := range windows {
			w := window
			evidenceResult.Evidence = append(evidenceResult.Evidence, evidence.Evidence{EvidenceID: w.ID, IP: w.IP, Type: "shared_access_window", Window: opts.Window.String(), CreatedAt: w.LastObservedAt.Format(time.RFC3339Nano), Severity: "info", Reason: "共享观测窗口，须经来源、独立信号及事件时身份校验", Samples: []string{}, SharedAccess: &w})
		}
		result.Evidence = len(evidenceResult.Evidence)
	}
	evidenceJSON, err := json.Marshal(evidenceResult)
	if err != nil {
		return result, err
	}
	riskResult, err := risk.Batch(bytes.NewReader(evidenceJSON))
	if err != nil {
		return result, fmt.Errorf("score risks: %w", err)
	}
	result.Snapshots = len(riskResult.Snapshots)
	if writer, ok := backend.(store.RouterObservationWriter); ok {
		routerOptions := evidence.RouterOptions{AsOf: result.StartedAt, ShadowMode: true}
		if resolver, available := backend.(interface {
			ResolveDeviceAt(context.Context, store.DomainObservation) (store.IdentityAttribution, bool, error)
		}); available {
			routerOptions.Resolve = func(event normalized.Event) evidence.RouterAssociation {
				item, found, resolveErr := resolver.ResolveDeviceAt(ctx, store.DomainObservation{IP: routerMaterializeString(event.Subject["ip"]), Timestamp: event.Timestamp, SensorID: routerMaterializeString(event.Observer["sensor_id"]), CampusID: firstRouterMaterializeString(event.Subject["campus_id"], event.Payload["campus_id"])})
				if resolveErr != nil || !found {
					return evidence.RouterAssociation{}
				}
				association := evidence.RouterAssociation{EndpointID: item.EndpointID, Quality: "dhcp_lease", Ambiguous: item.Conflict, Reason: item.ConflictReason}
				if strings.HasPrefix(item.EndpointID, "mac:") {
					association.MAC = strings.TrimPrefix(item.EndpointID, "mac:")
				}
				return association
			}
		}
		routerResult, routerErr := evidence.AnalyzeRouters(events, routerOptions)
		if routerErr != nil {
			return result, fmt.Errorf("aggregate router evidence: %w", routerErr)
		}
		if routerErr = writer.WriteRouterObservations(ctx, routerResult); routerErr != nil {
			return result, fmt.Errorf("persist router observations: %w", routerErr)
		}
		result.RouterEvidence, result.RouterAssessments = len(routerResult.Evidence), len(routerResult.Assessments)
	}
	if err := backend.WriteEvidence(ctx, evidenceResult.Evidence); err != nil {
		return result, fmt.Errorf("persist evidence: %w", err)
	}
	if err := backend.WriteRiskSnapshots(ctx, riskResult.Snapshots); err != nil {
		return result, fmt.Errorf("persist risk snapshots: %w", err)
	}
	cutoff := time.Now().UTC().Add(-opts.Window - time.Minute)
	if err := backend.ExpireRiskSnapshots(ctx, cutoff); err != nil {
		return result, fmt.Errorf("expire stale snapshots: %w", err)
	}
	result.CompletedAt = time.Now().UTC()
	runID := fmt.Sprintf("risk-materializer-%d", result.StartedAt.UnixNano())
	run := store.Run{RunID: runID, SensorID: opts.SensorID, StartedAt: result.StartedAt.Format(time.RFC3339Nano), FinishedAt: result.CompletedAt.Format(time.RFC3339Nano), EvidenceCount: result.Evidence, RiskCount: result.Snapshots, Normalized: store.NormalizedCounts{Read: result.Events, Emitted: result.Events, ByType: map[string]int{}}, RawRef: map[string]any{"kind": "risk-materializer", "window": opts.Window.String()}}
	if err := backend.WriteCollectorRun(ctx, run); err != nil {
		return result, fmt.Errorf("persist materializer run: %w", err)
	}
	return result, nil
}

func routerMaterializeString(value any) string {
	text, _ := value.(string)
	return text
}

func firstRouterMaterializeString(values ...any) string {
	for _, value := range values {
		if text := routerMaterializeString(value); text != "" {
			return text
		}
	}
	return ""
}

func queryWindow(value time.Duration) (string, error) {
	switch value {
	case 10 * time.Minute:
		return "10m", nil
	case time.Hour:
		return "1h", nil
	case 24 * time.Hour:
		return "24h", nil
	case 7 * 24 * time.Hour:
		return "7d", nil
	default:
		return "", fmt.Errorf("materializer window must be one of 10m, 1h, 24h, 7d")
	}
}
