package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// streamPositionConflict preserves the conflict sentinel while identifying the
// narrow index or body locator that failed. It never accepts event body bytes.
func streamPositionConflict(stage, kind string, indexedAt time.Time, ref StreamBodyRef, actualKey, actualHash string, classes ...string) error {
	epoch := ref.Epoch
	if epoch == "" {
		epoch, _, _ = strings.Cut(ref.Key, ":")
	}
	layout := ref.BodyLayout
	if layout == "" {
		layout = "v1"
	}
	stamp := "none"
	if !indexedAt.IsZero() {
		stamp = indexedAt.UTC().Format(time.RFC3339Nano)
	}
	expectedClass, actualClass := "reference", "observed"
	if len(classes) >= 2 {
		expectedClass, actualClass = classes[0], classes[1]
	}
	actualKeyDetail := ""
	if actualKey != "" && actualKey != ref.Key {
		actualKeyDetail = " actual_key=" + boundedPositionToken(actualKey)
	}
	actualHashDetail := ""
	if actualHash != "" {
		actualHashDetail = " actual_sha256=" + boundedPositionHash(actualHash)
	}
	return fmt.Errorf("%w: stage=%s kind=%s source_epoch=%s indexed_at=%s scope=%s event_key=%s ref=%s/%s/%s expected_sha256=%s%s%s expected_class=%s actual_class=%s",
		streamlog.ErrContentConflict,
		boundedPositionToken(stage), boundedPositionToken(kind), boundedPositionToken(epoch), stamp,
		boundedPositionToken(ref.Scope), boundedPositionToken(ref.Key),
		boundedPositionToken(ref.Class), boundedPositionToken(ref.Month), boundedPositionToken(layout),
		boundedPositionHash(ref.SHA256), actualKeyDetail, actualHashDetail,
		boundedPositionToken(expectedClass), boundedPositionToken(actualClass))
}

// Only fixed-format source metadata may appear literally in logs. Unexpected
// content, control characters and long values are represented by a digest.
func boundedPositionToken(value string) string {
	if value == "" {
		return "none"
	}
	if len(value) > 128 {
		return positionDigest(value)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':' {
			continue
		}
		return positionDigest(value)
	}
	return value
}

func boundedPositionHash(value string) string {
	if value == "" {
		return "none"
	}
	if len(value) != 64 {
		return positionDigest(value)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return positionDigest(value)
	}
	return value
}

func positionDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:8])
}
