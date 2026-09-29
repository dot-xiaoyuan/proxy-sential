package controlplane

import (
	"proxy-sentinel/internal/store"
	"testing"
)

func TestManagedIdentityConfigurationBounds(t *testing.T) {
	valid := managedIdentityConfig{Kind: "online_equipment", IdentityScope: store.IdentityScope{Source: "4k:test", SensorID: "sensor", CampusID: "campus", AccessDomain: "domain"}, UserCIDRs: []string{"192.168.0.0/24"}, MaxRecords: 10000}
	if valid.validate() != nil {
		t.Fatal("valid config rejected")
	}
	for _, mutate := range []func(*managedIdentityConfig){
		func(c *managedIdentityConfig) { c.CampusID = "" },
		func(c *managedIdentityConfig) { c.UserCIDRs = []string{"0.0.0.0/0"} },
		func(c *managedIdentityConfig) { c.MaxRecords = 10001 },
		func(c *managedIdentityConfig) { c.Kind = "redis" },
		func(c *managedIdentityConfig) {
			c.Kind = "complete_inventory"
			c.InventoryURL = "http://example.com/inventory"
		},
	} {
		c := valid
		mutate(&c)
		if c.validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
