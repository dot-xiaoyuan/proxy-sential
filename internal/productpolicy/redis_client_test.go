package productpolicy

import (
	"encoding/json"
	"testing"
)

func TestJSONStringSizeMatchesEncodingJSON(t *testing.T) {
	for _, input := range []string{"中文😀", "", "<>&\u2028\u2029", "\xff\xfe", "\x00\n\r\b\t\f\"\\"} {
		encoded, err := json.Marshal(input)
		if err != nil || jsonStringBytes(input) != len(encoded) {
			t.Fatal("escaped byte count differs", err)
		}
	}
}
