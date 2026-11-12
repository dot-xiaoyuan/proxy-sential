// hardware-report replays attributed, exported standard fields without network
// access. Its JSON explicitly distinguishes field replay from original packets.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

type signal struct {
	fingerprint.EvidenceSignal
	Value string `json:"value"`
}
type sample struct {
	ID              string          `json:"id"`
	IP              string          `json:"ip"`
	MAC             string          `json:"mac"`
	Origin          string          `json:"origin"`
	Model           string          `json:"model"`
	Attribution     string          `json:"attribution"`
	Sensor          string          `json:"sensor"`
	Domain          string          `json:"domain"`
	VLAN            json.RawMessage `json:"vlan"`
	ObservedAt      time.Time       `json:"observed_at"`
	AsOf            time.Time       `json:"as_of"`
	Evidence        []signal        `json:"evidence"`
	IdentityTrusted bool            `json:"identity_trusted"`
}
type row struct {
	ID         string                     `json:"id"`
	IP         string                     `json:"ip,omitempty"`
	MAC        string                     `json:"mac,omitempty"`
	Scope      string                     `json:"scope"`
	InputKind  string                     `json:"input_kind"`
	SkipReason string                     `json:"skip_reason,omitempty"`
	Result     fingerprint.HardwareResult `json:"result"`
}
type report struct {
	Version     string                             `json:"version"`
	InputKind   string                             `json:"input_kind"`
	AsOf        time.Time                          `json:"as_of"`
	Sources     []fingerprint.HardwareSourceReport `json:"sources"`
	Unsupported []fingerprint.HardwareUnsupported  `json:"unsupported"`
	Provenance  []fingerprint.BundleSource         `json:"source_provenance"`
	Rows        []row                              `json:"rows"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	input := flag.String("input", "", "JSONL exported fields or explicit attributed evidence; no pcap claim")
	output := flag.String("output", "", "JSON output (stdout if empty)")
	base := flag.String("build-v8-base", "", "verified V7 bundle to upgrade")
	bundleOutput := flag.String("bundle-output", "", "candidate V8 output path")
	version := flag.String("version", "", "new immutable bundle version")
	dataDir := flag.String("data-dir", "internal/fingerprint/data", "pinned catalog directory")
	asOf := flag.String("as-of", "", "fixed replay time RFC3339Nano (defaults current UTC)")
	flag.Parse()
	now := time.Now().UTC()
	if *asOf != "" {
		var err error
		now, err = time.Parse(time.RFC3339Nano, *asOf)
		if err != nil {
			return err
		}
	}
	if *base != "" {
		if *bundleOutput == "" || *version == "" {
			return fmt.Errorf("bundle-output and version required")
		}
		data, err := os.ReadFile(*base)
		if err != nil {
			return err
		}
		manifest, err := fingerprint.BuildV8Bundle(data, *bundleOutput, *version, now)
		if err != nil {
			return err
		}
		return writeJSON(*output, manifest)
	}
	catalog, err := os.ReadFile(*dataDir + "/hardware-catalog.json")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*dataDir + "/multisource-provenance.json")
	if err != nil {
		return err
	}
	extra, err := os.ReadFile(*dataDir + "/hardware-provenance.json")
	if err != nil {
		return err
	}
	h, err := fingerprint.ParseHardwareCatalog(catalog, raw, extra)
	if err != nil {
		return err
	}
	counts, unsupported := h.SourceReport()
	out := report{Version: h.Version, InputKind: "exported structured field replay; not original pcap or site acceptance", AsOf: now, Sources: counts, Unsupported: unsupported, Provenance: h.Sources}
	totals := map[string]*fingerprint.HardwareSourceReport{}
	for i := range out.Sources {
		totals[out.Sources[i].Source] = &out.Sources[i]
	}
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			return err
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 65536), 2<<20)
		line := 0
		for scan.Scan() {
			line++
			var s sample
			if err := json.Unmarshal(scan.Bytes(), &s); err != nil {
				return fmt.Errorf("line %d: %w", line, err)
			}
			r := row{ID: s.ID, IP: s.IP, MAC: s.MAC, Scope: s.Sensor + "/" + s.Domain + "/vlan=" + string(s.VLAN), InputKind: "exported attributed standard fields"}
			in := fingerprint.HardwareInput{IdentityTrusted: s.IdentityTrusted}
			for _, v := range s.Evidence {
				v.EvidenceSignal.Value = v.Value
				in.Evidence = append(in.Evidence, v.EvidenceSignal)
			}
			if len(in.Evidence) == 0 {
				field := map[string]string{"sadp": "sadp_model", "dns_sd": "dns_sd_model", "snmp": "snmp_model", "ssdp": "ssdp_model"}[s.Origin]
				if field == "" || s.Model == "" {
					r.SkipReason = "no supported hardware self-report field in exported row"
				} else if s.Attribution != "direct_l2" && s.Attribution != "direct" && s.Attribution != "mac" {
					r.SkipReason = "export does not establish trusted device attribution"
				} else {
					in.IdentityTrusted = true
					in.Evidence = []fingerprint.EvidenceSignal{{Protocol: s.Origin, Field: field, Value: s.Model, Direction: "device", Association: "direct", SourceFamily: s.Origin, EventID: s.ID, ObservedAt: s.ObservedAt}}
				}
			}
			r.Result = h.Evaluate(in, now)
			for _, c := range r.Result.SourceReports {
				if target := totals[c.Source]; target != nil {
					target.InputAvailable += c.InputAvailable
					target.Matched += c.Matched
					target.FormedType += c.FormedType
				}
			}
			out.Rows = append(out.Rows, r)
			if r.Result.Incomplete {
				return fmt.Errorf("line %d incomplete: %s", line, r.Result.Error)
			}
		}
		if err := scan.Err(); err != nil {
			return err
		}
	}
	return writeJSON(*output, out)
}
func writeJSON(path string, value any) error {
	var f *os.File
	var err error
	if path == "" {
		f = os.Stdout
	} else {
		f, err = os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
	}
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	return e.Encode(value)
}
