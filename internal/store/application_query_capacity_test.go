package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/appdomain"
)

func TestApplicationDatabaseMillionResultQueries(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_APP_QUERY_CAPACITY") != "1000000" {
		t.Skip("opt-in million result query test")
	}
	d := appIntegrationDB(t)
	ctx := context.Background()
	sensor := fmt.Sprintf("app-query-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	t.Cleanup(func() {
		cleanupApplicationTestData(ctx, d.store, sensor, false)
	})
	m := appdomain.Match{TargetType: "application", TargetID: "wechat", Name: "微信", Category: "communication"}
	mj, _ := json.Marshal(m)
	seed := fmt.Sprintf(`INSERT INTO application_observations(timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,observation_json,classification_revision,batch_id)
 SELECT now64(9)-INTERVAL 1 HOUR,%s,concat('query-',toString(number)),'main','10.0.0.1',concat('c',toString(intDiv(number,10))),'tls','weixin.qq.com','tls.sni','v1','wechat','application','微信','communication',toUInt64(10),toUInt64(20),concat('{"event_id":"query-',toString(number),'","timestamp":"',formatDateTime(now64(9)-INTERVAL 1 HOUR,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC'),'","sensor_id":"',%s,'","campus_id":"main","ip":"10.0.0.1","connection_id":"c',toString(intDiv(number,10)),'","event_type":"tls","domain":"weixin.qq.com","source_field":"tls.sni","bundle_version":"v1","upload_bytes":10,"download_bytes":20,"match":',%s,'}'),1,1 FROM numbers(1000000)`, chQuote(sensor), chQuote(sensor), chQuote(string(mj)))
	if err := d.store.ch.exec(ctx, seed); err != nil {
		t.Fatal(err)
	}
	q := appdomain.Query{From: now.Add(-2 * time.Hour), To: time.Now().UTC(), SensorID: sensor}
	if err := d.store.DrainApplicationConnectionReadModel(ctx); err != nil {
		t.Fatal(err)
	}
	d.syncConnectionReadModel = false
	start := time.Now()
	r, err := d.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("million report duration=%s", time.Since(start))
	if r.ObservationCount != 1000000 || len(r.Items) != 1 || r.Items[0].ConnectionCount != 100000 {
		t.Fatalf("bad million report: %+v", r)
	}
	start = time.Now()
	p, err := d.Page(ctx, q, appdomain.PageRequest{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("million first page duration=%s", time.Since(start))
	if len(p.Items) != 20 || p.Total != 1000000 || p.NextCursor == "" {
		t.Fatalf("bad page: %+v", p)
	}
	start = time.Now()
	p2, err := d.Page(ctx, q, appdomain.PageRequest{Limit: 20, Cursor: p.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("million next page duration=%s", time.Since(start))
	if len(p2.Items) != 20 || p2.Items[0].EventID == p.Items[0].EventID {
		t.Fatal("cursor did not advance")
	}
	start = time.Now()
	if err = d.Export(ctx, q, io.Discard); err != nil {
		t.Fatal(err)
	}
	t.Logf("million unknown export duration=%s", time.Since(start))
}
