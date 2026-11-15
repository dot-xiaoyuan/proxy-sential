package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/store"
)

func openProductRuntime() (string, error) {
	manager, err := fingerprint.OpenInstalledRuntime()
	if err != nil {
		return "", err
	}
	if manager == nil {
		return "", fmt.Errorf("product refresh requires the installed verified V8 fingerprint bundle")
	}
	manager.SetOffline(true)
	probe := fingerprint.EvaluateHardware(fingerprint.HardwareInput{}, time.Now().UTC())
	if probe.Incomplete || probe.SourceStatus != "verified_bundle" || probe.Version == "" {
		return "", fmt.Errorf("product refresh requires a verified V8 hardware catalog")
	}
	return probe.Version, nil
}

func prepareProductRefresh(sourcePath, outputPath string) error {
	if sourcePath == "" || sourcePath == outputPath {
		return fmt.Errorf("prepare-product requires distinct source-manifest and manifest paths")
	}
	version, err := openProductRuntime()
	if err != nil {
		return err
	}
	var manifest store.HardwareRepairManifest
	if err = readRepairJSON(sourcePath, &manifest); err != nil {
		return err
	}
	if err = manifest.Validate(); err != nil {
		return err
	}
	eligible := 0
	for i := range manifest.Entries {
		e := &manifest.Entries[i]
		if e.DHCPRecovery != nil || e.ProductRefreshVersion != "" {
			return fmt.Errorf("product preparation requires an original snapshot")
		}
		if e.Observation == nil {
			continue
		}
		clue, err := discovery.BuildIPProductClue(*e.Observation, time.Now().UTC())
		if err != nil {
			return err
		}
		if clue == nil {
			e.Observation = nil
			e.ExcludedReason = "not_verified_product_response"
			continue
		}
		e.ProductRefreshVersion = version
		eligible++
	}
	if err = manifest.Validate(); err != nil {
		return err
	}
	if err = writeRepairJSON(outputPath, manifest, true); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "prepared_product_refresh", "rows": len(manifest.Entries), "eligible": eligible, "excluded": len(manifest.Entries) - eligible, "rule_version": version, "manifest_sha256": manifestHash(manifest)})
}
