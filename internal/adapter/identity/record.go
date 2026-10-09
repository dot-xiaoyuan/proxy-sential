package identity

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"proxy-sentinel/internal/normalized"
	"unicode/utf8"
)

const maxJSONLRecordBytes = 16 * 1024 * 1024

// NormalizeRecord maps one parsed record through the same standard-event
// constructor as Convert, without buffering and decoding an entire inventory.
// Its output preserves the JSON input/output semantics of Convert, including
// invalid UTF-8 replacement, stable IDs and finite JSON confidence values.
// Input maps are read only; every returned event owns its mutable maps.
func NormalizeRecord(fields map[string]string, lineOffset int, opts Options) (normalized.Event, error) {
	validUTF8, fits := identityJSONRecordBudget(fields)
	if !fits {
		return normalized.Event{}, fmt.Errorf("scan identity jsonl: %w", bufio.ErrTooLong)
	}
	if !validUTF8 {
		// encoding/json's exact replacement and duplicate-key ordering are required
		// for stable event IDs. ToValidUTF8 would collapse consecutive invalid bytes.
		raw, err := json.Marshal(fields)
		if err != nil {
			return normalized.Event{}, err
		}
		var canonicalFields map[string]string
		if err := json.Unmarshal(raw, &canonicalFields); err != nil {
			return normalized.Event{}, err
		}
		fields = canonicalFields
	}
	event, err := convertRecord(fields, lineOffset, opts)
	if err != nil {
		return normalized.Event{}, err
	}
	if math.IsNaN(event.Confidence) || math.IsInf(event.Confidence, 0) {
		return normalized.Event{}, fmt.Errorf("identity confidence must be finite")
	}
	if len(event.Observer) == 0 {
		event.Observer = nil
	}
	if !utf8.ValidString(opts.Source) || !utf8.ValidString(opts.SensorID) {
		// Keep raw options while constructing the ID: invalid bytes are escaped by
		// canonical(), differently from already replaced valid Unicode strings.
		raw, err := json.Marshal(event)
		if err != nil {
			return normalized.Event{}, err
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			return normalized.Event{}, err
		}
	} else {
		// The JSON decoder used by Convert exposes numbers in RawRef as float64.
		event.RawRef["line_offset"] = float64(lineOffset)
	}
	return event, nil
}

// identityJSONRecordBudget measures default encoding/json string escaping,
// without allocating a serialized record. Scanner requires room beyond the
// complete JSON token, so the encoded record must be smaller than its maximum.
func identityJSONRecordBudget(fields map[string]string) (validUTF8, fits bool) {
	remaining := maxJSONLRecordBytes - 1 - 2 // object braces
	validUTF8 = true
	index := 0
	for key, value := range fields {
		if index > 0 {
			remaining--
		} // comma
		remaining-- // colon
		var valid bool
		remaining, valid, fits = consumeIdentityJSONString(key, remaining)
		if !fits {
			return false, false
		}
		validUTF8 = validUTF8 && valid
		remaining, valid, fits = consumeIdentityJSONString(value, remaining)
		if !fits {
			return false, false
		}
		validUTF8 = validUTF8 && valid
		index++
	}
	return validUTF8, remaining >= 0
}

func consumeIdentityJSONString(value string, budget int) (remaining int, validUTF8, fits bool) {
	remaining, validUTF8 = budget-2, true // quotes
	if remaining < 0 {
		return remaining, validUTF8, false
	}
	for i := 0; i < len(value); {
		cost := 1
		c := value[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"', '\\', '\b', '\f', '\n', '\r', '\t':
				cost = 2
			case '<', '>', '&':
				cost = 6
			default:
				if c < 0x20 {
					cost = 6
				}
			}
			i++
		} else {
			r, width := utf8.DecodeRuneInString(value[i:])
			cost = width
			i += width
			if r == utf8.RuneError && width == 1 {
				cost = 6
				validUTF8 = false
			} else if r == '\u2028' || r == '\u2029' {
				cost = 6
			}
		}
		remaining -= cost
		if remaining < 0 {
			return remaining, validUTF8, false
		}
	}
	return remaining, validUTF8, true
}
