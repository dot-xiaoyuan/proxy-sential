// passive-hardware-audit replays locally exported discovery observations without
// connecting to a database or modifying a projection. It does not assert truth
// labels, physical-device counts, or field deployment acceptance.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"proxy-sentinel/internal/discovery"
)

type inputRow struct {
	AsOf        time.Time             `json:"as_of"`
	Observation discovery.Observation `json:"observation"`
}
type auditRow struct {
	Identity string                  `json:"identity"`
	IPs      []string                `json:"ips"`
	State    discovery.HardwareState `json:"result"`
}
type skippedRow struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac,omitempty"`
	Source  string `json:"source"`
	EventID string `json:"event_id"`
	Reason  string `json:"reason"`
}
type report struct {
	Boundary          string         `json:"boundary"`
	AsOf              time.Time      `json:"as_of"`
	Observations      int            `json:"observations"`
	TrustedIdentities int            `json:"trusted_scoped_identities"`
	Identified        int            `json:"identified"`
	MissingScope      int            `json:"incomplete_scope_identities"`
	Types             map[string]int `json:"types"`
	Rows              []auditRow     `json:"rows"`
	Skipped           []skippedRow   `json:"excluded_observations"`
}

func audit(r io.Reader) (report, error) {
	out := report{Boundary: "local retained-observation replay; not original-pcap replay, physical-device census, accuracy, recall, or field acceptance", Types: map[string]int{}, Rows: []auditRow{}, Skipped: []skippedRow{}}
	facts := map[string]map[string]discovery.HardwareFact{}
	ips := map[string]map[string]bool{}
	scanner := bufio.NewScanner(io.LimitReader(r, 64*1024*1024+1))
	scanner.Buffer(make([]byte, 65536), 2*1024*1024)
	bytesRead := 0
	for scanner.Scan() {
		bytesRead += len(scanner.Bytes()) + 1
		if bytesRead > 64*1024*1024 || out.Observations >= 20000 {
			return out, fmt.Errorf("audit exceeds 64 MiB or 20000 observations; no complete report")
		}
		var row inputRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return out, err
		}
		if row.AsOf.IsZero() {
			return out, fmt.Errorf("snapshot time is required")
		}
		if out.AsOf.IsZero() {
			out.AsOf = row.AsOf
		} else if !out.AsOf.Equal(row.AsOf) {
			return out, fmt.Errorf("input spans different snapshots")
		}
		out.Observations++
		o := row.Observation
		if o.ObservedAt.After(row.AsOf) {
			return out, fmt.Errorf("observation follows snapshot time")
		}
		reason := ""
		if len(o.Evidence.RawRef) == 0 {
			reason = "缺少权威原文引用，未进入硬件重算"
		}
		f, err := discovery.HardwareFactFromObservation(o)
		if err != nil {
			return out, err
		}
		if f == nil && reason == "" {
			reason = "缺少同作用域可信身份或设备响应证据；保留原线索"
		}
		if reason != "" {
			out.Skipped = append(out.Skipped, skippedRow{IP: o.IP, MAC: o.MAC, Source: o.Origin, EventID: o.EventID, Reason: reason})
			continue
		}
		if facts[f.IdentityKey] == nil {
			facts[f.IdentityKey] = map[string]discovery.HardwareFact{}
			ips[f.IdentityKey] = map[string]bool{}
		}
		old, ok := facts[f.IdentityKey][f.FactKey]
		if !ok || discovery.HardwareFactNewer(*f, old) {
			facts[f.IdentityKey][f.FactKey] = *f
		}
		if o.IP != "" {
			ips[f.IdentityKey][o.IP] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := make([]discovery.HardwareFact, 0, len(facts[key]))
		for _, fact := range facts[key] {
			values = append(values, fact)
		}
		state, err := discovery.EvaluateHardwareFacts(values, nil, out.AsOf)
		if err != nil {
			return out, err
		}
		addresses := []string{}
		for address := range ips[key] {
			addresses = append(addresses, address)
		}
		sort.Strings(addresses)
		out.Rows = append(out.Rows, auditRow{Identity: key, IPs: addresses, State: state})
		if state.VLAN == "" {
			out.MissingScope++
		}
		if state.HardwareTypeStatus == "identified" {
			out.Identified++
			out.Types[state.HardwareType]++
		}
	}
	out.TrustedIdentities = len(out.Rows)
	return out, nil
}

func main() {
	input := flag.String("input", "", "local JSONL {as_of,observation} snapshot")
	output := flag.String("output", "", "complete JSON report; stdout if empty")
	flag.Parse()
	if *input == "" {
		fmt.Fprintln(os.Stderr, "--input is required")
		os.Exit(2)
	}
	f, err := os.Open(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	result, err := audit(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	raw = append(raw, '\n')
	if *output != "" {
		err = os.WriteFile(*output, raw, 0600)
	} else {
		_, err = os.Stdout.Write(raw)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
