package sharedaccess

import (
	"sort"
	"strings"
	"time"
)

// FeatureSample counts distinct standard events, never the packet_count carried
// by an aggregate event. Buckets retain temporal coexistence independently.
type FeatureSample struct {
	Count   int     `json:"count"`
	Buckets []int64 `json:"buckets"`
}

func (w *Window) ObserveFeature(family, value string, at time.Time) bool {
	if value == "" {
		return true
	}
	if w.Samples == nil {
		w.Samples = map[string]map[string]FeatureSample{}
	}
	if w.Samples[family] == nil {
		w.Samples[family] = map[string]FeatureSample{}
	}
	values := w.Samples[family]
	sample, exists := values[value]
	if !exists && len(values) >= 32 {
		return false
	}
	if sample.Count < 3 {
		sample.Count++
	}
	bucket := at.Unix() / 5
	found := false
	for _, existing := range sample.Buckets {
		if existing == bucket {
			found = true
			break
		}
	}
	if !found {
		if len(sample.Buckets) >= 128 {
			return false
		}
		sample.Buckets = append(sample.Buckets, bucket)
	}
	values[value] = sample
	return true
}

func (w Window) repeatedTogether(family string, values []string) bool {
	if family == "ttl_path" {
		for i, left := range values {
			ld, li, valid := TTLPathFamily(left)
			if !valid {
				continue
			}
			for _, right := range values[i+1:] {
				rd, ri, valid := TTLPathFamily(right)
				if valid && ld == rd && li != ri && w.repeatedFeatureTogether(family, []string{left, right}) {
					return true
				}
			}
		}
		return false
	}
	return w.repeatedFeatureTogether(family, values)
}

// HasRepeatedFeature exposes the conservative coexistence gate to storage
// prefilters without duplicating its count, bucket and timing semantics.
func (w Window) HasRepeatedFeature(family string) bool {
	values := map[string][]string{
		"ua_os": w.UAOS, "ttl_path": w.TTLPaths, "tcp_stack": w.TCPStacks,
		"tls_stack": w.TLSStacks, "dhcp_stack": w.DHCPProfiles,
	}[family]
	return w.repeatedTogether(family, values)
}

func (w Window) repeatedFeatureTogether(family string, values []string) bool {
	if len(values) < 2 {
		return false
	}
	sets := make([]map[int64]bool, 0, len(values))
	for _, value := range values {
		sample := w.Samples[family][value]
		if sample.Count < 3 {
			continue
		}
		bins := map[int64]bool{}
		for _, bin := range sample.Buckets {
			if bin < w.From.Unix()/5 || bin > w.To.Unix()/5 {
				return false
			}
			bins[bin] = true
		}
		if len(bins) >= 2 {
			sets = append(sets, bins)
		}
	}
	// A family proves diversity when any two different values repeatedly
	// coexist. Requiring every observed value to coexist makes one transient
	// or malformed fingerprint suppress an otherwise valid pair.
	for i := range sets {
		for j := i + 1; j < len(sets); j++ {
			if repeatedBucketMatches(sets[i], sets[j], 6) >= 2 {
				return true
			}
		}
	}
	return false
}

func repeatedBucketMatches(left, right map[int64]bool, tolerance int64) int {
	a := make([]int64, 0, len(left))
	b := make([]int64, 0, len(right))
	for value := range left {
		a = append(a, value)
	}
	for value := range right {
		b = append(b, value)
	}
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	matches := 0
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i] < b[j]-tolerance:
			i++
		case b[j] < a[i]-tolerance:
			j++
		default:
			matches++
			i++
			j++
		}
	}
	return matches
}

// CoexistingDeviceModels excludes a 24h union and brand aliases of one model.
// Each admitted model must participate in a repeated pair in this window.
func (w Window) CoexistingDeviceModels() []string {
	canonical := map[string]FeatureSample{}
	for value, sample := range w.Samples["device_model"] {
		parts := strings.SplitN(value, "|", 4)
		if len(parts) != 4 || strings.TrimSpace(parts[3]) == "" {
			continue
		}
		model := strings.ToLower(strings.TrimSpace(parts[3]))
		old := canonical[model]
		if sample.Count > old.Count {
			old.Count = sample.Count
		}
		old.Buckets = append(old.Buckets, sample.Buckets...)
		canonical[model] = old
	}
	probe := w
	probe.Samples = map[string]map[string]FeatureSample{"device_model": canonical}
	models := make([]string, 0, len(canonical))
	for model := range canonical {
		models = append(models, model)
	}
	sort.Strings(models)
	admitted := map[string]bool{}
	for i, left := range models {
		for _, right := range models[i+1:] {
			if probe.repeatedTogether("device_model", []string{left, right}) {
				admitted[left] = true
				admitted[right] = true
			}
		}
	}
	result := []string{}
	for _, model := range models {
		if admitted[model] {
			result = append(result, model)
		}
	}
	return result
}
