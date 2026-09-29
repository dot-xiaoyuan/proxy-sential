// srun-api-probe performs read-only native management API checks.
//
// Modes:
//
//	total       aggregate online count only (original behavior)
//	capability  endpoint shapes and the authoritative-inventory contract verdict
//	account     bounded account-scoped observation; field presence only, no values
//
// The probe never issues a control request: no drop, disable, logout or release.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/srunapi"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "", "private native API configuration file")
	mode := flag.String("mode", "total", "probe mode: total, capability or account")
	account := flag.String("account", "", "account for --mode account")
	strict := flag.Bool("strict", false, "exit non-zero unless the probe verdict is usable")
	flag.Parse()

	switch *mode {
	case "total", "capability", "account":
	default:
		return fmt.Errorf("unsupported probe mode %q", *mode)
	}
	if *mode == "account" && strings.TrimSpace(*account) == "" {
		return fmt.Errorf("--account is required for --mode account")
	}

	client, err := openClient(*path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	switch *mode {
	case "total":
		count, err := client.OnlineTotal(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"status": "ok", "mode": "total", "online_total": count,
			"certificate_verification": "explicit_leaf_pin", "read_only": true,
		})
	case "capability":
		return runCapability(ctx, client, *strict)
	default:
		return runAccount(ctx, client, *account, *strict)
	}
}

func openClient(path string) (*srunapi.Client, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("probe configuration unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<10 {
		return nil, fmt.Errorf("probe configuration must be a private regular file of at most 64 KiB")
	}
	var cfg struct {
		Endpoint        string `json:"endpoint"`
		AppID           string `json:"app_id"`
		AppSecret       string `json:"app_secret"`
		CertificateFile string `json:"certificate_file"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil {
		return nil, fmt.Errorf("invalid probe configuration")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("trailing probe configuration")
	}
	if !strings.HasPrefix(cfg.Endpoint, "https://") {
		return nil, fmt.Errorf("HTTPS endpoint required")
	}
	cert, err := os.ReadFile(cfg.CertificateFile)
	if err != nil {
		return nil, fmt.Errorf("pinned management certificate unavailable")
	}
	hc, err := srunapi.NewCertificatePinnedClient(cert)
	if err != nil {
		return nil, err
	}
	return srunapi.New(cfg.Endpoint, cfg.AppID, cfg.AppSecret, hc)
}

type endpointCapability struct {
	Endpoint   string                        `json:"endpoint"`
	Capability srunapi.EquipmentCapabilities `json:"capability"`
	Error      string                        `json:"error,omitempty"`
}

type capabilityReport struct {
	Status      string                   `json:"status"`
	Mode        string                   `json:"mode"`
	OnlineTotal *int64                   `json:"online_total,omitempty"`
	OnlineError string                   `json:"online_total_error,omitempty"`
	Endpoints   []endpointCapability     `json:"endpoints"`
	Verdict     srunapi.InventoryVerdict `json:"verdict"`
	ReadOnly    bool                     `json:"read_only"`
}

func runCapability(ctx context.Context, client *srunapi.Client, strict bool) error {
	report := capabilityReport{Status: "ok", Mode: "capability", Endpoints: []endpointCapability{}, ReadOnly: true}
	if count, err := client.OnlineTotal(ctx); err == nil {
		report.OnlineTotal = &count
	} else {
		report.OnlineError = "aggregate online count unavailable"
	}

	type probe struct {
		endpoint string
		read     func(context.Context) (srunapi.EquipmentCapabilities, error)
	}
	probes := []probe{
		{"/api/v2/base/online-equipment", client.InspectEquipmentCapabilities},
		{"/api/v2/base/online-data", client.InspectOnlineDataCapabilities},
	}
	observed := []srunapi.EquipmentCapabilities{}
	for _, item := range probes {
		capability, err := item.read(ctx)
		entry := endpointCapability{Endpoint: item.endpoint, Capability: capability}
		if err != nil {
			// A failed endpoint must not hide the other one, but it also cannot
			// contribute to the verdict.
			entry.Error = "endpoint read failed"
		} else {
			observed = append(observed, capability)
		}
		report.Endpoints = append(report.Endpoints, entry)
	}
	report.Verdict = srunapi.BuildInventoryVerdict(observed, nil)

	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(report); err != nil {
		return err
	}
	if strict && report.Verdict.Completeness != "proven" {
		return fmt.Errorf("authoritative inventory contract is not proven: %s", strings.Join(report.Verdict.Blockers, "; "))
	}
	return nil
}

type accountReport struct {
	Status          string   `json:"status"`
	Mode            string   `json:"mode"`
	Rows            int      `json:"rows"`
	Fields          []string `json:"fields"`
	MissingRequired []string `json:"missing_required_fields,omitempty"`
	Complete        bool     `json:"complete"`
	AbsenceVerified bool     `json:"absence_verified"`
	Blocker         string   `json:"blocker,omitempty"`
	ReadOnly        bool     `json:"read_only"`
}

func runAccount(ctx context.Context, client *srunapi.Client, account string, strict bool) error {
	observation, err := client.OnlineEquipment(ctx, account)
	if err != nil {
		return fmt.Errorf("account observation failed: %w", err)
	}
	// Only field names are reported. Row values are never printed.
	fields := map[string]bool{}
	for _, row := range observation.Rows {
		for key := range row {
			fields[strings.ToLower(strings.TrimSpace(key))] = true
		}
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)

	report := accountReport{
		Status: "ok", Mode: "account", Rows: len(observation.Rows),
		Fields: names, Complete: observation.Complete,
		AbsenceVerified: observation.AbsenceVerified, Blocker: observation.Blocker,
		ReadOnly: true,
	}
	for _, required := range []string{"rad_online_id", "session_id", "user_name", "add_time"} {
		if !fields[required] {
			report.MissingRequired = append(report.MissingRequired, required)
		}
	}
	if !fields["ip"] && !fields["ipv6"] && !fields["ip6"] {
		report.MissingRequired = append(report.MissingRequired, "ip|ipv6|ip6")
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return err
	}
	if strict && (observation.Blocker != "" || len(report.MissingRequired) > 0) {
		return fmt.Errorf("account observation is not an authoritative inventory: %s", observation.Blocker)
	}
	return nil
}
