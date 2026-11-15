package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"proxy-sentinel/internal/store"
)

func prepareDHCPRecovery(sourcePath, recordsPath, outputPath string) error {
	if sourcePath == "" || recordsPath == "" || sourcePath == outputPath {
		return fmt.Errorf("prepare-dhcp requires distinct source-manifest, dhcp-records and manifest paths")
	}
	var manifest store.HardwareRepairManifest
	if err := readRepairJSON(sourcePath, &manifest); err != nil {
		return err
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	f, err := os.Open(recordsPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > store.HardwareRepairMaxSnapshotBytes {
		return fmt.Errorf("DHCP proof input exceeds 16 MiB")
	}
	proofs := map[string]store.HardwareDHCPRecovery{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*store.HardwareRepairMaxRowBytes)
	for scanner.Scan() {
		var record struct {
			EventID string `json:"event_id"`
			store.HardwareDHCPRecovery
		}
		if err = json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return err
		}
		if record.EventID == "" || len(proofs) >= store.HardwareRepairMaxRows {
			return fmt.Errorf("invalid or excessive DHCP records")
		}
		if _, exists := proofs[record.EventID]; exists {
			return fmt.Errorf("duplicate DHCP original event")
		}
		proofs[record.EventID] = record.HardwareDHCPRecovery
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	eligible := 0
	for i := range manifest.Entries {
		e := &manifest.Entries[i]
		if e.Observation == nil {
			continue
		}
		proof, ok := proofs[e.EventID]
		if !ok {
			e.ExcludedReason = "original_record_not_found"
			e.Observation = nil
			continue
		}
		if _, err = store.RecoverHardwareDHCPObservation(*e.Observation, proof); err != nil {
			e.ExcludedReason = err.Error()
			e.Observation = nil
			continue
		}
		e.DHCPRecovery = &proof
		eligible++
	}
	if err = manifest.Validate(); err != nil {
		return err
	}
	if err = writeRepairJSON(outputPath, manifest, true); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "prepared_dhcp_recovery", "rows": len(manifest.Entries), "eligible": eligible, "excluded": len(manifest.Entries) - eligible, "manifest_sha256": manifestHash(manifest)})
}
