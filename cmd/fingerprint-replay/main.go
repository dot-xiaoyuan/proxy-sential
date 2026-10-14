// fingerprint-replay compares the same local snapshot with and without the catalog.
// It emits aggregate measurements only, never endpoint identifiers or input values.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"proxy-sentinel/internal/fingerprint"
	"runtime"
	"time"
)

func main() {
	path := flag.String("input", "", "JSONL endpoint attributes from an isolated local snapshot")
	libraryDir := flag.String("library-dir", "", "optional installed offline library directory")
	flag.Parse()
	if *libraryDir != "" {
		fingerprint.NewManager(*libraryDir)
	}
	f, err := os.Open(*path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	inputs := []fingerprint.Signals{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	for scanner.Scan() {
		var a map[string]any
		if err = json.Unmarshal(scanner.Bytes(), &a); err != nil {
			panic(err)
		}
		str := func(k string) string { v, _ := a[k].(string); return v }
		p := map[string][]string{}
		for k, v := range map[string]string{"http_server": "server", "http_title": "title", "tls_subject": "certificate_subject", "tls_issuer": "certificate_issuer", "snmp_sysdescr": "snmp_sysdescr", "snmp_sysoid": "snmp_sysoid", "mdns_model": "mdns_model", "http_body": "http_body", "ssh_banner": "ssh_banner"} {
			if x := str(v); x != "" {
				p[k] = []string{x}
			}
		}
		inputs = append(inputs, fingerprint.Signals{UserAgents: []string{str("user_agent")}, Hostnames: []string{str("hostname"), str("client_fqdn")}, DHCPVendorClass: str("vendor_class"), DHCPRequestedOptions: str("requested_options"), Hints: []string{str("model"), str("os"), str("server")}, ProtocolFields: p})
	}
	if err = scanner.Err(); err != nil {
		panic(err)
	}
	base := *fingerprint.Default()
	if err = base.LoadCatalog(nil); err != nil {
		panic(err)
	}
	results := []map[string]any{}
	for _, variant := range []struct {
		name string
		lib  *fingerprint.Library
	}{{"baseline_without_catalog", &base}, {"expanded_catalog", fingerprint.Default()}} {
		for _, s := range inputs {
			variant.lib.IdentifySignals(s)
		} // warm the exact same inputs
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		started := time.Now()
		hits, conflicts, identified := 0, 0, 0
		bySource := map[string]int{}
		for _, s := range inputs {
			r := variant.lib.IdentifySignals(s)
			if len(r.SourceMatches) > 0 {
				hits++
			}
			if r.Conflict {
				conflicts++
			}
			if r.DeviceType != "" {
				identified++
			}
			seen := map[string]bool{}
			for _, m := range r.SourceMatches {
				if !seen[m.SourceID] {
					bySource[m.SourceID]++
					seen[m.SourceID] = true
				}
			}
		}
		elapsed := time.Since(started)
		runtime.ReadMemStats(&after)
		results = append(results, map[string]any{"variant": variant.name, "endpoints": len(inputs), "elapsed_ms": float64(elapsed.Microseconds()) / 1000, "endpoints_per_second": float64(len(inputs)) / elapsed.Seconds(), "allocated_bytes": after.TotalAlloc - before.TotalAlloc, "allocations": after.Mallocs - before.Mallocs, "matched_endpoints": hits, "identified_endpoints": identified, "conflict_endpoints": conflicts, "source_endpoints": bySource})
	}
	data, _ := json.MarshalIndent(map[string]any{"scope": "in-process recognition replay; queue and database not measured", "go_version": runtime.Version(), "results": results}, "", "  ")
	fmt.Println(string(data))
}
