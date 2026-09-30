package discovery

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewDeviceViewSerializesEmptyCollectionsAsArrays(t *testing.T) {
	data, err := json.Marshal(newDeviceView("device-test", time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"addresses", "capabilities", "protocols", "observations"} {
		if !strings.Contains(string(data), `"`+field+`":[]`) {
			t.Fatalf("%s must be an empty array: %s", field, data)
		}
	}
}
