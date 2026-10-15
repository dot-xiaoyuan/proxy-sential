package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"time"
)

func (w EnrichmentWorker) readSNMPProduct(ctx context.Context, o Observation) (map[string]any, error) {
	var config []byte
	var encrypted string
	e := w.Repository.DB.QueryRowContext(ctx, `SELECT config,encrypted_secret FROM discovery_sources WHERE enabled AND node=$1 AND config->>'address'=$2 AND config->>'site'=$3 AND config->>'domain'=$4 AND coalesce(config->>'identity_vlan','')=$5 ORDER BY id LIMIT 1`, o.Node, o.IP, o.Site, o.Domain, o.VLAN).Scan(&config, &encrypted)
	if e != nil {
		return nil, fmt.Errorf("matching SNMP credentials unavailable")
	}
	if len(w.MasterKey) < 16 {
		return nil, fmt.Errorf("credential key unavailable")
	}
	var source Source
	if e = json.Unmarshal(config, &source); e != nil {
		return nil, e
	}
	secret, e := decryptDiscoverySecret(encrypted, w.MasterKey)
	if e != nil {
		return nil, fmt.Errorf("SNMP credential decoding failed")
	}
	c := &gosnmp.GoSNMP{Target: o.IP, Port: 161, Timeout: 2 * time.Second, Retries: 0, Context: ctx, MaxOids: 8, Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv}
	if source.Version == "2c" {
		if secret.Community == "" {
			return nil, fmt.Errorf("SNMP credential unavailable")
		}
		c.Version = gosnmp.Version2c
		c.Community = secret.Community
	} else if source.Version == "3" && source.Username != "" && len(secret.Auth) >= 8 && len(secret.Privacy) >= 8 {
		c.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: source.Username, AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: secret.Auth, PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: secret.Privacy}
	} else {
		return nil, fmt.Errorf("SNMP credential incomplete")
	}
	if e = c.Connect(); e != nil {
		return nil, fmt.Errorf("SNMP connection failed")
	}
	defer c.Conn.Close()
	// Bounded GET only. Entity index 1 is a supplementary clue, never a claim
	// that an unobserved entity inventory was walked or fully covered.
	packet, e := c.Get([]string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.47.1.1.1.1.12.1", "1.3.6.1.2.1.47.1.1.1.1.13.1"})
	if e != nil || packet == nil || packet.Error != gosnmp.NoError {
		return nil, fmt.Errorf("SNMP GET failed")
	}
	return snmpProductPayload(packet), nil
}
