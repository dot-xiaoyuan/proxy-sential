package legacy4k

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// OnlineSessionID preserves the legacy observation identity when no login
// generation exists. Known generations use a versioned, unambiguous identity.
func OnlineSessionID(instance, session, loginTime string) string {
	if loginTime == "" {
		return instance + ":" + session
	}
	raw, _ := json.Marshal([]string{session, loginTime})
	sum := sha256.Sum256(raw)
	return instance + ":v2:" + hex.EncodeToString(sum[:])
}
