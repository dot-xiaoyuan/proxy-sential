// Summarize a frozen, read-only discovery export without exposing device IDs.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
)

type modelCount struct {
	Protocol, Model                         string
	Observations, Trusted, MissingOwnership int
	identities                              map[string]bool
}

func run() error {
	fromRaw := flag.String("from", "", "inclusive RFC3339 start of the frozen sample")
	toRaw := flag.String("to", "", "exclusive RFC3339 end of the frozen sample")
	flag.Parse()
	from, fromErr := time.Parse(time.RFC3339Nano, *fromRaw)
	to, toErr := time.Parse(time.RFC3339Nano, *toRaw)
	if fromErr != nil || toErr != nil || !from.Before(to) || to.Sub(from) > 24*time.Hour {
		return fmt.Errorf("a fixed observation window of at most 24 hours is required")
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<20+1))
	if err != nil {
		return err
	}
	if len(input) > 64<<20 {
		return fmt.Errorf("input exceeds 64 MiB")
	}
	hash := sha256.Sum256(input)
	models := make(map[[2]string]*modelCount)
	confirmed := make(map[string]bool)
	stream := bufio.NewScanner(bytes.NewReader(input))
	stream.Buffer(make([]byte, 65536), 256*1024)
	count := 0
	for stream.Scan() {
		count++
		if count > 20000 {
			return fmt.Errorf("input exceeds 20000 observations or the export was truncated")
		}
		var row discovery.Observation
		if err := json.Unmarshal(stream.Bytes(), &row); err != nil {
			return fmt.Errorf("invalid observation on row %d: %w", count, err)
		}
		if row.ObservedAt.Before(from) || !row.ObservedAt.Before(to) || row.Withdrawn {
			return fmt.Errorf("row %d is outside the frozen input boundary", count)
		}
		audit, err := discovery.AuditHardwareObservation(row, to)
		if err != nil {
			return err
		}
		if audit.FieldReplay.Incomplete {
			return fmt.Errorf("hardware catalog did not evaluate row %d", count)
		}
		fact, err := discovery.HardwareFactFromObservation(row)
		if err != nil {
			return err
		}
		trusted := fact != nil && len(row.Evidence.RawRef) > 0
		if trusted && audit.Result.Model != "" && audit.Result.TypeStatus == "identified" {
			confirmed[fact.IdentityKey] = true
		}
		if audit.FieldReplay.Model != "" {
			continue
		}
		for _, signal := range audit.RuleInputs {
			switch signal.Field {
			case "dhcp_product_model", "dns_sd_model", "sadp_model", "ssdp_model":
			default:
				continue
			}
			model := strings.Join(strings.Fields(signal.Value), " ")
			if model == "" || len(model) > 128 {
				continue
			}
			key := [2]string{row.Origin, strings.ToLower(model)}
			entry := models[key]
			if entry == nil {
				entry = &modelCount{Protocol: row.Origin, Model: model, identities: make(map[string]bool)}
				models[key] = entry
			}
			entry.Observations++
			if trusted {
				entry.identities[fact.IdentityKey] = true
			} else {
				entry.MissingOwnership++
			}
		}
	}
	if err := stream.Err(); err != nil {
		return err
	}
	ranks := make([]modelCount, 0, len(models))
	for _, entry := range models {
		entry.Trusted = len(entry.identities)
		ranks = append(ranks, *entry)
	}
	sort.Slice(ranks, func(i, j int) bool {
		a, b := ranks[i], ranks[j]
		if a.Observations != b.Observations {
			return a.Observations > b.Observations
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Model < b.Model
	})
	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	return out.Encode(map[string]any{
		"from": from, "to": to, "observations": count, "sha256": fmt.Sprintf("%x", hash),
		"matched_scoped_model_identities": len(confirmed), "unmatched_groups": len(ranks),
		"top_unmatched": ranks[:min(30, len(ranks))],
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
