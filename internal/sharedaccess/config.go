package sharedaccess

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Load registers capture scope independently from event-supplied claims.
// An absent file disables evaluation; a malformed configured file fails startup.
func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil {
		return Config{}, err
	}
	if len(raw) > 1024*1024 {
		return Config{}, fmt.Errorf("shared source configuration exceeds 1 MiB")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var cfg Config
	if err = dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
	var trailing any
	if err = dec.Decode(&trailing); err != io.EOF {
		return Config{}, fmt.Errorf("unexpected trailing shared source configuration")
	}
	if cfg.SchemaVersion != "shared-access-sources/v1" || strings.TrimSpace(cfg.Version) == "" || cfg.FreshnessSeconds < 1 || cfg.FreshnessSeconds > 3600 || len(cfg.Sources) == 0 {
		return Config{}, fmt.Errorf("invalid shared source configuration header")
	}
	seen := map[[2]string]Source{}
	for _, s := range cfg.Sources {
		for _, v := range []string{s.SensorID, s.Source, s.CampusID, s.AccessDomain} {
			if v == "" || strings.TrimSpace(v) != v {
				return Config{}, fmt.Errorf("shared source scope fields must be nonempty and trimmed")
			}
		}
		key := [2]string{s.SensorID, s.Source}
		if _, ok := seen[key]; ok {
			return Config{}, fmt.Errorf("duplicate or ambiguous shared source %s/%s", s.SensorID, s.Source)
		}
		seen[key] = s
	}
	return cfg, nil
}
