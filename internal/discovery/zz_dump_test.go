package discovery

import (
	"os"
	"testing"
	"time"
)

func TestDumpListSQL(t *testing.T) {
	sel, err := buildIndexedDeviceSelection(DeviceQuery{Window: 24 * time.Hour, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	sql := sel.CTE + ` SELECT count(*) FROM matched`
	_ = os.WriteFile("/tmp/list-query.sql", []byte(sql), 0644)
	t.Logf("args=%v len=%d", sel.Args, len(sql))
}
