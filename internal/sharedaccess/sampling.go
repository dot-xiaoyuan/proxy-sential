package sharedaccess

import "time"

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
			common := 0
			for bin := range sets[i] {
				if sets[j][bin] {
					common++
				}
			}
			if common >= 2 {
				return true
			}
		}
	}
	return false
}
