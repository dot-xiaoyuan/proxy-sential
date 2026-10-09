package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/srunapi"
)

type nativeConfigEntry struct {
	AllowLegacyRedisReplay bool   `json:"allow_legacy_redis_replay,omitempty"`
	TestAccount            string `json:"test_account,omitempty"`
	ConnectorID            string `json:"connector_id"`
	CampusID               string `json:"campus_id"`
	AccessDomain           string `json:"access_domain"`
	Endpoint               string `json:"endpoint"`
	CredentialSource       string `json:"credential_source,omitempty"`
	AppID                  string `json:"app_id"`
	AppSecret              string `json:"app_secret"`
	CertificateFile        string `json:"certificate_file"`
	InventoryURL           string `json:"inventory_url,omitempty"`
	InventoryToken         string `json:"inventory_token,omitempty"`
	RedisURL               string `json:"redis_url,omitempty"`
	OnlineList             string `json:"online_list"`
	ReadyKey               string `json:"ready_key"`
	MaxRecords             int    `json:"max_records"`
	DropType               string `json:"drop_type"`
}

// LoadNativeActions performs no network requests. Secrets remain in the private
// configuration file and runtime, never in public connector responses.
func LoadNativeActions(path string) (map[string]NativeActionRuntime, func(), error) {
	clients := []*legacy4k.RedisOnlineClient{}
	closeAll := func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}
	fail := func(message string) (map[string]NativeActionRuntime, func(), error) {
		closeAll()
		return nil, func() {}, fmt.Errorf("native configuration: %s", message)
	}
	if path == "" {
		return nil, closeAll, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fail("file unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return fail("private regular file of at most 64 KiB required")
	}
	dec := json.NewDecoder(io.LimitReader(f, 65537))
	dec.DisallowUnknownFields()
	var entries []nativeConfigEntry
	if dec.Decode(&entries) != nil || len(entries) == 0 || len(entries) > 16 {
		return fail("invalid connector list")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fail("trailing data")
	}
	result := map[string]NativeActionRuntime{}
	for _, c := range entries {
		if strings.TrimSpace(c.ConnectorID) == "" || c.CampusID == "" || c.AccessDomain == "" || c.MaxRecords < 1 || c.MaxRecords > 10000 || c.DropType != "radius" {
			return fail("explicit connector, source scope, bounded inventory and radius capability required")
		}
		if _, exists := result[c.ConnectorID]; exists {
			return fail("duplicate connector")
		}
		if !strings.HasPrefix(c.Endpoint, "https://") {
			return fail("HTTPS management endpoint required")
		}
		cert, err := os.ReadFile(c.CertificateFile)
		if err != nil {
			return fail("certificate unavailable")
		}
		hc, err := srunapi.NewCertificatePinnedClient(cert)
		if err != nil {
			return fail("invalid certificate pin")
		}
		appID, appSecret := c.AppID, c.AppSecret
		if c.CredentialSource != "" && c.CredentialSource != "static" && c.CredentialSource != "4k_database" {
			return fail("invalid credential source")
		}
		if c.CredentialSource == "4k_database" {
			if appID != "" || appSecret != "" {
				return fail("database credentials cannot be combined with static application keys")
			}
			appID, appSecret = "database-provider", "deferred"
		}
		native, err := srunapi.New(c.Endpoint, appID, appSecret, hc)
		if c.CredentialSource == "4k_database" && err == nil {
			native = native.WithCredentialsProvider(func(context.Context) (string, string, error) {
				return "", "", fmt.Errorf("4K credential provider not bound")
			})
		}
		if err != nil {
			return fail("invalid management origin or credentials")
		}
		if c.InventoryURL != "" {
			if c.RedisURL != "" || c.OnlineList != "" || c.ReadyKey != "" {
				return fail("API inventory cannot be combined with a Redis fallback")
			}
			reader, err := srunapi.NewInventoryHTTP(c.InventoryURL, c.InventoryToken, c.CampusID, c.AccessDomain, c.MaxRecords, hc)
			if err != nil {
				return fail("invalid complete inventory API configuration")
			}
			result[c.ConnectorID] = NativeActionRuntime{CredentialsFrom4K: c.CredentialSource == "4k_database", TestAccount: c.TestAccount, Probe: native.OnlineTotal, Client: native, CampusID: c.CampusID, AccessDomain: c.AccessDomain, DropType: c.DropType, Read: reader.Read}
			continue
		}
		if c.InventoryToken != "" || c.OnlineList == "" || c.ReadyKey == "" {
			return fail("explicit complete inventory API or legacy inventory configuration required")
		}
		managementURL, _ := url.Parse(c.Endpoint)
		redisURL, parseErr := url.Parse(c.RedisURL)
		managementIP, managementErr := netip.ParseAddr(managementURL.Hostname())
		var redisIP netip.Addr
		var redisErr error
		if parseErr == nil {
			redisIP, redisErr = netip.ParseAddr(redisURL.Hostname())
		} else {
			redisErr = parseErr
		}
		if !c.AllowLegacyRedisReplay || managementErr != nil || !managementIP.IsLoopback() || redisErr != nil || !redisIP.IsLoopback() {
			return fail("legacy Redis inventory requires explicit isolated loopback replay mode; production requires an existing inventory API")
		}
		// Kept for existing isolated replay installations only. API failures
		// never enter this branch or fall back to direct database access.
		ro, err := redis.ParseURL(c.RedisURL)
		if err != nil {
			return fail("invalid inventory connection")
		}
		ro.DialTimeout = 3 * time.Second
		ro.ReadTimeout = 3 * time.Second
		ro.WriteTimeout = 3 * time.Second
		ro.MaxRetries = -1
		ro.PoolSize = 2
		rc := legacy4k.NewRedisOnlineClient(ro)
		clients = append(clients, rc)
		result[c.ConnectorID] = NativeActionRuntime{CredentialsFrom4K: c.CredentialSource == "4k_database", TestAccount: c.TestAccount, Probe: native.OnlineTotal, Client: native, CampusID: c.CampusID, AccessDomain: c.AccessDomain, DropType: c.DropType, Read: func(ctx context.Context) (legacy4k.OnlineInventory, error) {
			inventory, err := legacy4k.ReadOnlineInventory(ctx, rc, c.OnlineList, c.ReadyKey, c.MaxRecords)
			if err == nil {
				err = waitNativeObservation(ctx, inventory.ObservedAt)
			}
			return inventory, err
		}}
	}
	return result, closeAll, nil
}
