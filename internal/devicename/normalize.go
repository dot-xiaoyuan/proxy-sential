package devicename

import (
	"bytes"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// Normalize converts Zeek-style hexadecimal escapes used by DHCP host names
// into displayable text. It returns the detected encoding only when the input
// was transformed, allowing callers to retain the original evidence.
func Normalize(value string) (normalized, encoding string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	raw, escaped, ok := escapedBytes(value)
	if !ok {
		return "", ""
	}
	if !escaped {
		if valid(value) {
			return value, ""
		}
		return "", ""
	}
	if utf8.Valid(raw) {
		normalized = string(raw)
		encoding = "utf-8-escape"
	} else {
		decoded, err := simplifiedchinese.GB18030.NewDecoder().Bytes(raw)
		if err != nil || !utf8.Valid(decoded) {
			return "", ""
		}
		normalized = string(decoded)
		encoding = "gb18030-escape"
	}
	normalized = strings.TrimSpace(normalized)
	if !valid(normalized) {
		return "", ""
	}
	return normalized, encoding
}

func escapedBytes(value string) ([]byte, bool, bool) {
	var result bytes.Buffer
	escaped := false
	for index := 0; index < len(value); {
		if index+4 <= len(value) && value[index] == '\\' && value[index+1] == 'x' {
			decoded := make([]byte, 1)
			if _, err := hex.Decode(decoded, []byte(value[index+2:index+4])); err != nil {
				return nil, false, false
			}
			result.WriteByte(decoded[0])
			escaped = true
			index += 4
			continue
		}
		r, size := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && size == 1 {
			return nil, false, false
		}
		result.WriteString(value[index : index+size])
		index += size
	}
	return result.Bytes(), escaped, true
}

func valid(value string) bool {
	if value == "" || len(value) > 253 || !utf8.ValidString(value) || strings.ContainsRune(value, unicode.ReplacementChar) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
