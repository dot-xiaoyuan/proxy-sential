package fingerprint

import "testing"

func TestHistoryBackfillRequiresExplicitOptIn(t *testing.T) {
	for _, value := range []string{"", "false", "invalid", "true", " TRUE "} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PROXY_SENTINEL_FINGERPRINT_HISTORY_BACKFILL", value)
			want := value == "true" || value == " TRUE "
			if HistoryBackfillEnabled() != want {
				t.Fatalf("unexpected history policy for %q", value)
			}
		})
	}
}
