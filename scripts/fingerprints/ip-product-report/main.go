// ip-product-report audits frozen, scoped response observations offline. Its
// output is an IP product interpretation, never a count of physical devices.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"proxy-sentinel/internal/discovery"
	"time"
)

func run() error {
	input := flag.String("input", "", "JSONL scoped discovery observations")
	output := flag.String("output", "", "audit JSONL output")
	allProtocols := flag.Bool("all-protocols", false, "also audit hardware fields and attribution for each protocol; offline only")
	cutoff := flag.String("as-of", "", "required fixed RFC3339 cutoff")
	flag.Parse()
	now, err := time.Parse(time.RFC3339Nano, *cutoff)
	if err != nil {
		return err
	}
	if *input == "" || *output == "" || *input == *output {
		return fmt.Errorf("distinct input and output paths required")
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() > 64<<20 {
		return fmt.Errorf("input exceeds 64 MiB")
	}
	out, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 65536), 65536)
	enc := json.NewEncoder(out)
	count := 0
	for s.Scan() {
		count++
		if count > 10000 {
			return fmt.Errorf("input exceeds 10000 observations")
		}
		var o discovery.Observation
		if err = json.Unmarshal(s.Bytes(), &o); err != nil {
			return fmt.Errorf("row %d: %w", count, err)
		}
		clue, e := discovery.BuildIPProductClue(o, now)
		status, reason := "evaluated", ""
		if e != nil {
			status, reason = "evaluation_failed", e.Error()
		} else if clue == nil {
			status, reason = "excluded", "requires verified response IP, scope, original event and nonfuture evidence"
		}
		hash := sha256.Sum256(s.Bytes())
		row := map[string]any{"input_kind": "offline_scoped_observation_replay", "as_of": now, "ip": o.IP, "vlan": o.VLAN, "event_id": o.EventID, "input_sha256": hex.EncodeToString(hash[:]), "status": status, "reason": reason, "product_clue": clue, "physical_identity_confirmed": false}
		if *allProtocols {
			audit, err := discovery.AuditHardwareObservation(o, now)
			if err != nil {
				return fmt.Errorf("row %d: %w", count, err)
			}
			row["hardware_audit"] = audit
			row["origin"] = o.Origin
			row["mac"] = o.MAC
			row["sensor"] = o.Node
			row["domain"] = o.Domain
		}
		if err = enc.Encode(row); err != nil {
			return err
		}
	}
	if err = s.Err(); err != nil {
		return err
	}
	return out.Sync()
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
