package discovery

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func isSegmentKeyedPassiveSegment(segment streamlog.Segment) bool {
	if segment.Source != "passive-discovery" || len(segment.Events) == 0 {
		return false
	}
	count := 0
	for _, event := range segment.Events {
		if !normalized.IsDiscoveryProjectionEvent(event) {
			return false
		}
		count++
		if !strings.HasPrefix(event.EventID, "stream3-") {
			return false
		}
	}
	return count > 0
}

func hasSegmentKeyedPassiveEvent(segment streamlog.Segment) bool {
	if segment.Source != "passive-discovery" {
		return false
	}
	for _, event := range segment.Events {
		if strings.HasPrefix(event.EventID, "stream3-") {
			return true
		}
	}
	return false
}

func isSegmentKeyedDeviceSegment(segment streamlog.Segment) bool {
	if segment.Source != "device-signals" || !segment.RawIsStandardEvents || len(segment.Events) == 0 {
		return false
	}
	count := 0
	for _, event := range segment.Events {
		if normalized.IsDiscoveryProjectionEvent(event) {
			count++
			if !strings.HasPrefix(event.EventID, "stream4-") {
				return false
			}
		} else if strings.HasPrefix(event.EventID, "stream4-") {
			return false
		}
	}
	return count > 0
}

func hasSegmentKeyedDeviceEvent(segment streamlog.Segment) bool {
	for _, event := range segment.Events {
		if strings.HasPrefix(event.EventID, "stream4-") {
			return true
		}
	}
	return false
}

func verifyStream4PreparedSegment(id string, segment streamlog.Segment, prepared []streamPreparedDiscovery) error {
	if !isSegmentKeyedDeviceSegment(segment) || len(prepared) == 0 || len(prepared) > streamlog.MaxSegmentEvents || len(segment.Events) > streamlog.MaxSegmentEvents ||
		segment.SourcePath == "" || segment.FileID == "" || segment.StartOffset < 0 || segment.EndOffset <= segment.StartOffset ||
		segment.SourceGeneration > math.MaxInt64 || segment.AcceptedAt.IsZero() ||
		segment.ArchiveMonth != segment.AcceptedAt.UTC().Format("200601") ||
		streamlog.SourceSegmentID(segment) != id {
		return fmt.Errorf("invalid stream4 source interval: %w", streamlog.ErrContentConflict)
	}
	count := 0
	for _, event := range segment.Events {
		if normalized.IsDiscoveryProjectionEvent(event) {
			count++
		}
	}
	if count != len(prepared) {
		return fmt.Errorf("stream4 projection subset changed: %w", streamlog.ErrContentConflict)
	}
	firstScope := prepared[0].Receipt.Scope
	if firstScope == "" {
		return fmt.Errorf("stream4 capture scope missing: %w", streamlog.ErrContentConflict)
	}
	for ordinal, item := range prepared {
		key := fmt.Sprintf("%s:stream4-%s-%d", segment.Epoch, id, ordinal)
		if item.Receipt.Key != key || item.Receipt.Scope != firstScope {
			return fmt.Errorf("stream4 event key or scope conflicts with source interval: %w", streamlog.ErrContentConflict)
		}
		if _, err := hex.DecodeString(item.Receipt.Hash); err != nil || len(item.Receipt.Hash) != 64 {
			return fmt.Errorf("stream4 event hash invalid: %w", streamlog.ErrContentConflict)
		}
	}
	return nil
}

// verifyStream3PreparedSegment binds every key to this journal source interval
// before a keyless projection or archive confirmation can trust the manifest.
func verifyStream3PreparedSegment(id string, segment streamlog.Segment, prepared []streamPreparedDiscovery) error {
	if !isSegmentKeyedPassiveSegment(segment) || len(prepared) != len(segment.Events) ||
		len(prepared) == 0 || len(prepared) > streamlog.MaxPassiveSegmentEvents ||
		segment.SourcePath == "" || segment.FileID == "" || segment.StartOffset < 0 || segment.EndOffset <= segment.StartOffset ||
		segment.SourceGeneration > math.MaxInt64 || segment.AcceptedAt.IsZero() ||
		segment.ArchiveMonth != segment.AcceptedAt.UTC().Format("200601") ||
		streamlog.SourceSegmentID(segment) != id {
		return fmt.Errorf("invalid stream3 source interval: %w", streamlog.ErrContentConflict)
	}
	firstScope := prepared[0].Receipt.Scope
	if firstScope == "" {
		return fmt.Errorf("stream3 capture scope missing: %w", streamlog.ErrContentConflict)
	}
	for ordinal, item := range prepared {
		key := fmt.Sprintf("%s:stream3-%s-%d", segment.Epoch, id, ordinal)
		if item.Receipt.Key != key || item.Receipt.Scope != firstScope {
			return fmt.Errorf("stream3 event key or scope conflicts with source interval: %w", streamlog.ErrContentConflict)
		}
		if _, err := hex.DecodeString(item.Receipt.Hash); err != nil || len(item.Receipt.Hash) != 64 {
			return fmt.Errorf("stream3 event hash invalid: %w", streamlog.ErrContentConflict)
		}
	}
	return nil
}

func stream3ScopeAndHashes(items []streamPreparedDiscovery) (string, []byte, error) {
	if len(items) == 0 || len(items) > streamlog.MaxPassiveSegmentEvents {
		return "", nil, streamlog.ErrContentConflict
	}
	scope := items[0].Receipt.Scope
	hashes := make([]byte, 0, len(items)*32)
	for _, item := range items {
		if scope == "" || item.Receipt.Scope != scope {
			return "", nil, streamlog.ErrContentConflict
		}
		raw, err := hex.DecodeString(item.Receipt.Hash)
		if err != nil || len(raw) != 32 {
			return "", nil, streamlog.ErrContentConflict
		}
		hashes = append(hashes, raw...)
	}
	return scope, hashes, nil
}

// A compatible rollback release can confirm a stream3 segment from its
// immutable marker and manifest even when its own producer still emits stream2.
func (p StreamDiscoveryProjector) confirmStream3Archive(ctx context.Context, id string, segment streamlog.Segment) error {
	return p.confirmSegmentKeyedArchive(ctx, id, segment, "stream3")
}

func (p StreamDiscoveryProjector) confirmStream4Archive(ctx context.Context, id string, segment streamlog.Segment) error {
	return p.confirmSegmentKeyedArchive(ctx, id, segment, "stream4")
}

func (p StreamDiscoveryProjector) confirmSegmentKeyedArchive(ctx context.Context, id string, segment streamlog.Segment, scheme string) error {
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		return err
	}
	if scheme == "stream3" {
		err = verifyStream3PreparedSegment(id, segment, prepared)
	} else {
		err = verifyStream4PreparedSegment(id, segment, prepared)
	}
	if err != nil {
		return err
	}
	var hash, markerScheme string
	err = p.DB.QueryRowContext(ctx, `SELECT content_sha256,passive_key_scheme FROM stream_projection_segments WHERE segment_id=$1`, id).Scan(&hash, &markerScheme)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s projection marker missing: %w", scheme, streamlog.ErrUnconfirmed)
	}
	if err != nil {
		return err
	}
	if hash != streamProjectionSegmentHash(segment, prepared) || scheme != markerScheme {
		return streamlog.ErrContentConflict
	}
	keys := make([]string, len(prepared))
	for i, item := range prepared {
		keys[i] = item.Receipt.Key
	}
	reader := Repository{DB: p.DB}
	var receipts map[string]map[string]any
	if scheme == "stream4" {
		receipts, err = reader.streamSegmentReceiptsWithoutAuxiliaryChecks(ctx, segment.Epoch, prepared[0].Receipt.Scope, keys)
	} else {
		receipts, err = reader.streamSegmentReceipts(ctx, segment.Epoch, prepared[0].Receipt.Scope, keys)
	}
	if err != nil {
		return err
	}
	if len(receipts) != len(prepared) {
		return streamlog.ErrUnconfirmed
	}
	for _, item := range prepared {
		receipt, found := receipts[item.Receipt.Key]
		if !found || receipt["content_sha256"] != item.Receipt.Hash ||
			// pgx stores timestamptz at microsecond precision; the journal keeps nanoseconds.
			!receipt["first_accepted_at"].(time.Time).Equal(segment.AcceptedAt.UTC().Truncate(time.Microsecond)) ||
			!bytes.Equal(receipt["body_ref"].(json.RawMessage), streamDiscoveryBodyRef(segment, item.Receipt)) {
			return streamlog.ErrContentConflict
		}
	}
	return nil
}

// The segment marker is bound as a pgx timestamptz and truncated to a
// microsecond. Changes and sampled receipts pass through JSON timestamptz
// conversion, which can round upward by one microsecond.
func streamAcceptedAtMatches(marker, candidate time.Time) bool {
	delta := candidate.Sub(marker)
	return delta >= 0 && delta <= time.Microsecond
}
