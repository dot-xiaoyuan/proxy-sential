package discovery

import (
	"strconv"
	"strings"

	"proxy-sentinel/internal/streamlog"
)

// ParsePassiveStream3Key accepts only the canonical segment ID and ordinal
// encoded in a passive event key. The producer remains on stream2 until all
// stream3 readers, archive checks and case guards are compatible.
func ParsePassiveStream3Key(epoch, key string) (string, int, bool) {
	return parseStreamSegmentKey(epoch, key, "stream3")
}

// ParseDeviceStream4Key locates one device discovery event within its
// immutable source segment. Ordinals count only discovery projection events.
func ParseDeviceStream4Key(epoch, key string) (string, int, bool) {
	id, ordinal, ok := parseStreamSegmentKey(epoch, key, "stream4")
	return id, ordinal, ok && ordinal < streamlog.MaxSegmentEvents
}

func parseStreamSegmentKey(epoch, key, scheme string) (string, int, bool) {
	if epoch == "" || !strings.HasPrefix(key, epoch+":"+scheme+"-") {
		return "", 0, false
	}
	rest := strings.TrimPrefix(key, epoch+":"+scheme+"-")
	if len(rest) < 66 || len(rest) > 69 || rest[64] != '-' {
		return "", 0, false
	}
	for i := 0; i < 64; i++ {
		if c := rest[i]; c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return "", 0, false
			}
		}
	}
	ordinalText := rest[65:]
	ordinal, err := strconv.Atoi(ordinalText)
	if err != nil || ordinal < 0 || ordinal >= streamlog.MaxPassiveSegmentEvents || strconv.Itoa(ordinal) != ordinalText {
		return "", 0, false
	}
	return rest[:64], ordinal, true
}
