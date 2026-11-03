// discovery-tail-recovery repairs only an explicitly audited shutdown tail.
// Stop its Kafka normalized-event consumer and let deliveries settle first;
// the original journal remains the authoritative evidence and recovery input.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

type tailEntry struct {
	ID    string `json:"id"`
	Hash  string `json:"content_sha256"`
	Start int64  `json:"start_offset"`
	End   int64  `json:"end_offset"`
}

type tailPlan struct {
	Epoch      string      `json:"epoch"`
	SourcePath string      `json:"source_path"`
	FileID     string      `json:"file_id"`
	From       int64       `json:"from_offset"`
	To         int64       `json:"to_offset"`
	Entries    []tailEntry `json:"entries"`
}

func validatePlan(p tailPlan) error {
	if p.Epoch == "" || p.SourcePath == "" || p.FileID == "" || p.From < 0 || p.To <= p.From || len(p.Entries) == 0 || len(p.Entries) > 300 {
		return errors.New("invalid bounded shutdown tail")
	}
	position := p.From
	seen := map[string]bool{}
	for _, e := range p.Entries {
		if len(e.ID) != 64 || len(e.Hash) != 64 || seen[e.ID] || e.Start != position || e.End <= e.Start {
			return errors.New("tail has a gap, duplicate or invalid witness")
		}
		seen[e.ID] = true
		position = e.End
	}
	if position != p.To {
		return errors.New("tail does not reach the fixed shutdown cursor")
	}
	return nil
}

func loadEntry(j *streamlog.Journal, p tailPlan, e tailEntry) (streamlog.State, error) {
	s, err := j.Load(e.ID)
	if err != nil {
		return s, err
	}
	b := s.Segment
	if s.ContentSHA256 != e.Hash || !s.Committed || s.Released || b.Quarantined ||
		b.Epoch != p.Epoch || b.Source != "passive-discovery" || b.SourcePath != p.SourcePath || b.FileID != p.FileID ||
		b.StartOffset != e.Start || b.EndOffset != e.End || b.AcceptedAt.IsZero() || len(b.Events) == 0 || len(b.Events) > streamlog.MaxPassiveSegmentEvents {
		return s, errors.New("journal body does not match audited shutdown tail")
	}
	return s, nil
}

func run(journalPath, planPath, auditPath string, execute bool) error {
	raw, err := os.ReadFile(planPath)
	if err != nil {
		return err
	}
	var plan tailPlan
	if err = json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	if err = validatePlan(plan); err != nil {
		return err
	}
	j, err := streamlog.Open(journalPath)
	if err != nil {
		return err
	}
	// Verify the entire bounded selection before the first external write.
	total := 0
	for _, entry := range plan.Entries {
		s, err := loadEntry(j, plan, entry)
		if err != nil {
			return err
		}
		total += len(s.Segment.Events)
	}
	fmt.Printf("verified segments=%d events=%d execute=%t\n", len(plan.Entries), total, execute)
	if !execute {
		return nil
	}
	if auditPath == "" {
		return errors.New("execution requires an audit output")
	}
	// A replay can overlap the last pre-stop segment. Force the existing
	// event-ID existence check; insert-block dedup alone cannot cover different
	// Kafka batching. The consumer must remain stopped throughout this repair.
	if err := os.Setenv("PROXY_SENTINEL_EVENT_ID_IDEMPOTENCY", "scan"); err != nil {
		return err
	}
	ch, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN")})
	if err != nil {
		return errors.New("cannot initialize normalized event store")
	}
	audit, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer audit.Close()
	writeAudit := func(entry tailEntry, at time.Time, count int, status string) error {
		err := json.NewEncoder(audit).Encode(map[string]any{"at": time.Now().UTC(), "id": entry.ID,
			"content_sha256": entry.Hash, "first_accepted_at": at, "events": count, "status": status})
		if err != nil {
			return err
		}
		return audit.Sync()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	for _, entry := range plan.Entries {
		s, err := loadEntry(j, plan, entry)
		if err != nil {
			return err
		}
		events := append([]normalized.Event(nil), s.Segment.Events...)
		if err := writeAudit(entry, s.Segment.AcceptedAt, len(events), "attempted"); err != nil {
			return err
		}
		if err := ch.WriteNormalizedEvents(ctx, events); err != nil {
			_ = writeAudit(entry, s.Segment.AcceptedAt, len(events), "unconfirmed")
			return errors.New("normalized tail recovery not confirmed; retain journal and retry by event ID")
		}
		if err := writeAudit(entry, s.Segment.AcceptedAt, len(events), "confirmed"); err != nil {
			return err
		}
		fmt.Printf("confirmed segment=%s events=%d\n", entry.ID, len(events))
	}
	return nil
}

func main() {
	journal := flag.String("journal", "", "existing passive journal")
	plan := flag.String("plan", "", "audited fixed-offset tail plan")
	audit := flag.String("audit", "", "append-only repair audit output")
	execute := flag.Bool("execute", false, "repair normalized events after stopping the consumer")
	flag.Parse()
	if *journal == "" || *plan == "" {
		fmt.Fprintln(os.Stderr, "journal and plan are required")
		os.Exit(2)
	}
	if err := run(*journal, *plan, *audit, *execute); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
