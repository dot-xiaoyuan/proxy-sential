package normalized

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ConnectionID requires the actual collector instance/boot identifier. Unknown
// instances are deliberately unmetered; a five tuple or an event ID is not enough.
func ConnectionID(sensor, collector, instance, sourceID string) string {
	if sensor == "" || instance == "" || sourceID == "" {
		return ""
	}
	raw, _ := json.Marshal([]string{sensor, collector, instance, sourceID})
	sum := sha256.Sum256(raw)
	return "conn-" + hex.EncodeToString(sum[:])
}
