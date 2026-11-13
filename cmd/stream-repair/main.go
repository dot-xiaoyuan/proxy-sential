// stream-repair reconciles one stopped source's ambiguous ClickHouse lane.
// It does not mark the journal acknowledged; the ingest stream worker must
// verify all consumers and finalize the segment afterward.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

func main() {
	journalDir := flag.String("journal", "", "durable stream journal directory")
	id := flag.String("segment-id", "", "exact segment id")
	laneName := flag.String("lane", "", "archive, search or risk-feature")
	settledScoped := flag.Bool("settled-scoped", false, "repair a settled archive, birth-aware search or packet risk feature with scoped row proof")
	flag.Parse()
	if err := run(*journalDir, *id, streamlog.Lane(*laneName), *settledScoped); err != nil {
		fmt.Fprintln(os.Stderr, "stream repair:", err)
		os.Exit(1)
	}
}

func run(directory, id string, lane streamlog.Lane, settledScoped bool) error {
	if directory == "" || id == "" || (lane != streamlog.Archive && lane != streamlog.Search && lane != "risk-feature") {
		return errors.New("journal, segment-id and ClickHouse lane are required")
	}
	if settledScoped && lane != streamlog.Archive && lane != streamlog.Search && lane != "risk-feature" {
		return errors.New("settled scoped repair supports only archive, search or packet risk-feature")
	}
	j, err := streamlog.Open(directory)
	if err != nil {
		return err
	}
	j.SetRawResolver(realtime.ResolveZeekSourceRaw)
	state, err := j.Load(id)
	if err != nil {
		return err
	}
	if err := validateRepairCandidate(state, lane, settledScoped); err != nil {
		return err
	}
	// The source lease excludes a running capture or concurrent drain process.
	release, err := j.AcquireSourceLease(state.Segment.Source, state.Segment.SourcePath)
	if err != nil {
		return err
	}
	defer release()
	ch, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN")})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if settledScoped && lane == streamlog.Archive {
		err = ch.ReconcileSettledStreamBody(ctx, id, state.Segment)
	} else if settledScoped && lane == streamlog.Search {
		err = ch.ReconcileSettledStreamSearch(ctx, id, state.Segment)
	} else if settledScoped && lane == "risk-feature" {
		err = ch.ReconcileSettledStreamRiskFeatures(ctx, id, state.Segment)
	} else if lane == "risk-feature" {
		err = ch.RetryProvenUnsentStreamRiskFeatures(ctx, id, state.Segment)
	} else {
		err = ch.RetryProvenUnsentStreamLane(ctx, id, state.Segment, lane)
	}
	if err != nil {
		return err
	}
	fmt.Printf("verified scoped repair segment=%s lane=%s events=%d; restart the ingest stream worker to confirm journal and PostgreSQL receipts\n", id, lane, len(state.Segment.Events))
	return nil
}

func validateRepairCandidate(state streamlog.State, lane streamlog.Lane, settledScoped bool) error {
	ackLane := lane
	if lane == "risk-feature" {
		if !state.Segment.RiskFeaturesRequired {
			return errors.New("segment has no risk-feature acknowledgement requirement")
		}
		if state.Segment.SplitRiskFeatures {
			ackLane = streamlog.RiskFeatures
		} else {
			ackLane = streamlog.Search
		}
	}
	if state.Released || !state.Committed || state.Acks[ackLane] != streamlog.Attempted || state.Segment.Quarantined {
		return errors.New("segment is not a committed, attempted repair candidate")
	}
	if lane == "risk-feature" && state.Acks[streamlog.Archive] != streamlog.Acked {
		return errors.New("risk feature repair requires a confirmed authoritative body")
	}
	if settledScoped && lane == streamlog.Search && state.Acks[streamlog.Archive] != streamlog.Acked {
		return errors.New("settled search repair requires a confirmed authoritative body")
	}
	if settledScoped && lane == "risk-feature" {
		if !state.Segment.SplitRiskFeatures || state.Acks[streamlog.Search] != streamlog.Acked {
			return errors.New("settled packet risk feature repair requires a split attempted feature lane and confirmed search")
		}
	}
	return nil
}
