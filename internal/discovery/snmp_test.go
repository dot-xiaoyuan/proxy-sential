package discovery

import (
	"context"
	"github.com/gosnmp/gosnmp"
	"strings"
	"testing"
	"time"
)

type fixtureWalker map[string][]gosnmp.SnmpPDU

func (w fixtureWalker) Walk(root string, f gosnmp.WalkFunc) error {
	for _, p := range w[root] {
		if e := f(p); e != nil {
			return e
		}
	}
	return nil
}
func TestFDBIsNotVLAN(t *testing.T) {
	root := "1.3.6.1.2.1.17.7.1.2.2.1.2"
	vlan := "1.3.6.1.2.1.17.7.1.4.2.1.3"
	w := fixtureWalker{root: {{Name: root + ".500.0.17.34.51.68.85", Value: 2}}, vlan: {{Name: vlan + ".0.10", Value: 500}}}
	s := Source{ID: "s", Node: "n", Site: "s", Domain: "d", IntervalSeconds: 300}
	p := PollTables(context.Background(), w, s, "snap", time.Now())
	for _, e := range p.Events {
		if e.Payload["origin"] == "fdb" && e.Subject["vlan"] != "10" {
			t.Fatal("FDB ID mistaken for VLAN")
		}
	}
	w[vlan] = append(w[vlan], gosnmp.SnmpPDU{Name: vlan + ".0.20", Value: 500})
	p = PollTables(context.Background(), w, s, "snap2", time.Now())
	for _, e := range p.Events {
		if e.Payload["origin"] == "fdb" && e.Subject["vlan"] != "" {
			t.Fatal("ambiguous VLAN assigned")
		}
	}
	for _, e := range p.Events {
		if strings.Contains(e.EventID, "500") {
			t.Fatal("unstable event identifier")
		}
	}
}
