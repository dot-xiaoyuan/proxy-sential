// fingerprint-replay compares the same local inputs with two offline libraries.
// It emits aggregate measurements only, never endpoint identifiers or input values.
//
// The baseline library is loaded from --library-dir as installed. When
// --fingerbank-json points at a compiled snapshot, the second variant keeps every
// other payload identical and swaps only fingerbank-dhcp.json, which is the same
// change ReplaceFingerbankSnapshot applies to a bundle.
//
// Input lines may carry an integer "weight" (how many observations share this
// fingerprint); rates are then reported both unweighted and weighted.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

type replayInput struct {
	signals fingerprint.Signals
	weight  int
}

func main() {
	path := flag.String("input", "", "JSONL endpoint attributes from an isolated local snapshot")
	libraryDir := flag.String("library-dir", "", "installed offline library directory")
	fingerbankJSON := flag.String("fingerbank-json", "", "optional compiled fingerbank-dhcp.json to compare")
	flag.Parse()
	if *path == "" || *libraryDir == "" {
		fmt.Fprintln(os.Stderr, "usage: fingerprint-replay --input <jsonl> --library-dir <dir> [--fingerbank-json <json>]")
		os.Exit(2)
	}
	inputs, err := readInputs(*path)
	if err != nil {
		panic(err)
	}
	version, err := bundleVersion(*libraryDir)
	if err != nil {
		panic(err)
	}
	baseline, err := loadLibrary(*libraryDir, version, nil)
	if err != nil {
		panic(err)
	}
	type variant struct {
		name string
		lib  *fingerprint.Library
	}
	variants := []variant{{"baseline", baseline}}
	if *fingerbankJSON != "" {
		override, readErr := os.ReadFile(*fingerbankJSON)
		if readErr != nil {
			panic(readErr)
		}
		expanded, loadErr := loadLibrary(*libraryDir, version, override)
		if loadErr != nil {
			panic(loadErr)
		}
		variants = append(variants, variant{"fingerbank-refreshed", expanded})
	}
	results := make([]map[string]any, 0, len(variants))
	for _, item := range variants {
		results = append(results, measure(item.name, item.lib, inputs))
	}
	data, _ := json.MarshalIndent(map[string]any{
		"scope":      "in-process recognition replay; queue and database not measured",
		"go_version": runtime.Version(),
		"library":    version,
		"inputs":     len(inputs),
		"results":    results,
	}, "", "  ")
	fmt.Println(string(data))
}

func readInputs(path string) ([]replayInput, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	inputs := []replayInput{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	for scanner.Scan() {
		var a map[string]any
		if err = json.Unmarshal(scanner.Bytes(), &a); err != nil {
			return nil, err
		}
		str := func(k string) string { v, _ := a[k].(string); return v }
		weight := 1
		if value, ok := a["weight"].(float64); ok && value >= 1 {
			weight = int(value)
		}
		p := map[string][]string{}
		for k, v := range map[string]string{"http_server": "server", "http_title": "title", "tls_subject": "certificate_subject", "tls_issuer": "certificate_issuer", "snmp_sysdescr": "snmp_sysdescr", "snmp_sysoid": "snmp_sysoid", "mdns_model": "mdns_model", "http_body": "http_body", "ssh_banner": "ssh_banner"} {
			if x := str(v); x != "" {
				p[k] = []string{x}
			}
		}
		inputs = append(inputs, replayInput{weight: weight, signals: fingerprint.Signals{
			UserAgents:           []string{str("user_agent")},
			Hostnames:            []string{str("hostname"), str("client_fqdn")},
			DHCPVendorClass:      str("vendor_class"),
			DHCPRequestedOptions: str("requested_options"),
			Hints:                []string{str("model"), str("os"), str("server")},
			ProtocolFields:       p,
		}})
	}
	return inputs, scanner.Err()
}

func bundleVersion(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return "", err
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		return "", err
	}
	return manifest.Version, nil
}

func loadLibrary(dir, version string, fingerbankOverride []byte) (*fingerprint.Library, error) {
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) }
	oui, err := read("oui.csv")
	if err != nil {
		return nil, err
	}
	rules, err := read("device-rules.json")
	if err != nil {
		return nil, err
	}
	aliases, err := read("brand-aliases.json")
	if err != nil {
		return nil, err
	}
	domains, err := read("domain-signatures.json")
	if err != nil {
		return nil, err
	}
	fingerbankData := fingerbankOverride
	if fingerbankData == nil {
		fingerbankData, err = read("fingerbank-dhcp.json")
		if err != nil {
			return nil, err
		}
	}
	return fingerprint.LoadWithDomainData(version, oui, rules, fingerbankData, aliases, domains)
}

func measure(name string, library *fingerprint.Library, inputs []replayInput) map[string]any {
	for _, item := range inputs {
		library.IdentifySignals(item.signals)
	} // warm the exact same inputs
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	matched, identified, osIdentified, conflicts := 0, 0, 0, 0
	weightedMatched, weightedIdentified, weightedOS, weightedConflicts := 0, 0, 0, 0
	weightedTotal := 0
	bySource := map[string]int{}
	byOS := map[string]int{}
	conflictDimensions := map[string]int{}
	resultSources := map[string]int{}
	for _, item := range inputs {
		weightedTotal += item.weight
		result := library.IdentifySignals(item.signals)
		if len(result.SourceMatches) > 0 {
			matched++
			weightedMatched += item.weight
		}
		if result.DeviceType != "" {
			identified++
			weightedIdentified += item.weight
		}
		if result.Source != "" {
			resultSources[result.Source] += item.weight
		}
		if result.OSFamily != "" {
			osIdentified++
			weightedOS += item.weight
			byOS[result.OSFamily] += item.weight
		}
		if result.Conflict {
			conflicts++
			weightedConflicts += item.weight
			for _, dimension := range result.ConflictDimensions {
				conflictDimensions[dimension]++
			}
		}
		seen := map[string]bool{}
		for _, match := range result.SourceMatches {
			if !seen[match.SourceID] {
				seen[match.SourceID] = true
				bySource[match.SourceID]++
			}
		}
	}
	elapsed := time.Since(started)
	runtime.ReadMemStats(&after)
	rate := func(value int) float64 {
		if weightedTotal == 0 {
			return 0
		}
		return float64(value) / float64(weightedTotal)
	}
	return map[string]any{
		"variant":                 name,
		"fingerprints":            len(inputs),
		"weighted_endpoints":      weightedTotal,
		"elapsed_ms":              float64(elapsed.Microseconds()) / 1000,
		"fingerprints_per_second": float64(len(inputs)) / elapsed.Seconds(),
		"allocated_bytes":         after.TotalAlloc - before.TotalAlloc,
		"allocations":             after.Mallocs - before.Mallocs,
		"matched_fingerprints":    matched,
		"identified_fingerprints": identified,
		"os_family_fingerprints":  osIdentified,
		"conflict_fingerprints":   conflicts,
		"matched_rate":            rate(weightedMatched),
		"identified_rate":         rate(weightedIdentified),
		"os_family_rate":          rate(weightedOS),
		"conflict_rate":           rate(weightedConflicts),
		"source_fingerprints":     bySource,
		"os_family_distribution":  topN(byOS, 15),
		"conflict_dimensions":     conflictDimensions,
		"result_sources":          resultSources,
	}
}

func topN(values map[string]int, n int) map[string]int {
	type pair struct {
		key   string
		count int
	}
	pairs := make([]pair, 0, len(values))
	for key, count := range values {
		pairs = append(pairs, pair{key, count})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].count > pairs[j].count })
	out := map[string]int{}
	for index, item := range pairs {
		if index >= n {
			break
		}
		out[item.key] = item.count
	}
	return out
}
