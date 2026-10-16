package sharedaccess

import (
	"regexp"
	"sort"
	"strings"
	"time"
)

var androidModel = regexp.MustCompile(`(?i);[ ]*([^;()]{1,64})[ ]+Build/`)
var modelHasLetter = regexp.MustCompile(`[A-Z]`)
var modelHasDigit = regexp.MustCompile(`[0-9]`)
var appleModel = regexp.MustCompile(`(iPhone[0-9]+,[0-9]+|iPad[0-9]+,[0-9]+)`)

// HandshakeFeatures never counts a browser, generic OS or TLS stack as a device.
func HandshakeFeatures(family, value string) map[string]string {
	out := map[string]string{}
	if family == "ja3" {
		if len(value) == 32 {
			out["tls_stack"] = "ja3:" + value
		}
		return out
	}
	if family != "user_agent" {
		return out
	}
	ua := strings.ToLower(value)
	os, model, brand, kind := "", "", "", "mobile"
	switch {
	case strings.Contains(ua, "android"):
		os = "Android"
		if m := androidModel.FindStringSubmatch(value); len(m) > 1 {
			model = strings.ToUpper(strings.Join(strings.Fields(m[1]), " "))
			for _, prefix := range []string{"SAMSUNG ", "HUAWEI ", "HONOR ", "XIAOMI ", "REDMI ", "GOOGLE "} {
				model = strings.TrimPrefix(model, prefix)
			}
			if !modelHasLetter.MatchString(model) || !modelHasDigit.MatchString(model) {
				model = ""
			}
			for _, generic := range []string{"ANDROID", "GENERIC", "EMULATOR", "SIMULATOR", "SDK"} {
				if strings.Contains(model, generic) {
					model = ""
				}
			}
		}
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		os = "iOS"
		model = appleModel.FindString(value)
		if model != "" {
			brand = "Apple"
		}
		if strings.HasPrefix(model, "iPad") {
			kind = "tablet"
		}
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "mac os") || strings.Contains(ua, "macintosh"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	}
	if os != "" {
		out["ua_os"] = os
	}
	if model != "" {
		// Brand comes from the canonical model, not variable browser wording.
		// Optional vendor text must never split one physical model into two.
		if os == "Android" {
			switch {
			case strings.HasPrefix(model, "SM-"), strings.HasPrefix(model, "GT-"):
				brand = "Samsung"
			case strings.HasPrefix(model, "PIXEL "):
				brand = "Google"
			}
		}
		out["device_model"] = strings.Join([]string{brand, os, kind, model}, "|")
	}
	return out
}

type CoverageFact struct {
	EventID  string     `json:"event_id,omitempty"`
	Source   string     `json:"source"`
	Instance string     `json:"instance"`
	IP       string     `json:"ip"`
	Coverage CoverageV2 `json:"coverage"`
}

// VerifyCoverage joins measured intervals only for actual contributors. Local
// proof may override global output trimming, never kernel loss or unknown stats.
func VerifyCoverage(w Window, cfg Config, facts []CoverageFact) []string {
	reasons := []string{}
	contributors := map[string]RecordRef{}
	for _, ref := range w.Records {
		contributors[ref.Source+"/"+ref.InstanceID] = ref
	}
	if len(contributors) == 0 {
		return []string{"capture_contributors_missing"}
	}
	for _, ref := range contributors {
		registered := false
		for _, source := range cfg.Sources {
			if source.Source == ref.Source && source.SensorID == w.SensorID && source.CampusID == w.CampusID && source.AccessDomain == w.AccessDomain {
				registered = true
			}
		}
		if !registered || ref.InstanceID == "" {
			reasons = append(reasons, "capture_source_unregistered:"+ref.Source)
			continue
		}
		intervals := []CoverageV2{}
		for _, f := range facts {
			if f.Source != ref.Source || f.Instance != ref.InstanceID || (f.IP != "" && f.IP != w.IP) {
				continue
			}
			c := f.Coverage
			if c.Complete() {
				intervals = append(intervals, c)
			}
		}
		sort.Slice(intervals, func(i, j int) bool { return intervals[i].From.Before(intervals[j].From) })
		end := w.From
		for _, c := range intervals {
			if c.From.After(end) {
				break
			}
			if c.To.After(end) {
				end = c.To
			}
		}
		if end.Before(w.To) || w.From.Equal(w.To) {
			reasons = append(reasons, "capture_interval_incomplete:"+ref.Source)
		}
		// Any unlocatable loss wins over per-IP proof, including conflicting replay.
		for _, f := range facts {
			c := f.Coverage
			if f.Source == ref.Source && f.Instance == ref.InstanceID && c.From.Before(w.To) && c.To.After(w.From) && (f.IP == "" || f.IP == w.IP) && (!c.KernelStatsKnown || c.Dropped > 0 || c.KeyDrops > 0 || c.ParseUnknown > 0 || c.Stopped || (f.IP == w.IP && !c.Complete())) {
				reasons = append(reasons, "capture_unlocated_loss:"+ref.Source)
				break
			}
		}
	}
	sort.Strings(reasons)
	return reasons
}

func (c Config) Freshness() time.Duration {
	if c.FreshnessSeconds > 0 {
		return time.Duration(c.FreshnessSeconds) * time.Second
	}
	return 3 * time.Minute
}
