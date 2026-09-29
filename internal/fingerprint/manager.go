package fingerprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultIEEEOUIURL   = "https://standards-oui.ieee.org/oui/oui.csv"
	defaultIEEEMAMURL   = "https://standards-oui.ieee.org/oui28/mam.csv"
	defaultIEEEMASURL   = "https://standards-oui.ieee.org/oui36/oui36.csv"
	defaultUAPCommitURL = "https://api.github.com/repos/ua-parser/uap-core/commits/master"
	defaultUAPRawURL    = "https://raw.githubusercontent.com/ua-parser/uap-core/%s/regexes.yaml"
)

type Status struct {
	ActiveDomainVersion     string               `json:"active_domain_version,omitempty"`
	PendingDomainVersion    string               `json:"pending_domain_version,omitempty"`
	DomainProcessingError   string               `json:"domain_processing_error,omitempty"`
	Version                 string               `json:"version"`
	Status                  string               `json:"status"`
	Source                  string               `json:"source"`
	Checksum                string               `json:"checksum"`
	UpdatedAt               string               `json:"updated_at,omitempty"`
	LastCheckedAt           string               `json:"last_checked_at,omitempty"`
	LastError               string               `json:"last_error,omitempty"`
	OfflineMode             bool                 `json:"offline_mode"`
	RuleCount               int                  `json:"rule_count"`
	RouterRuleCount         int                  `json:"router_rule_count"`
	ApplicationRuleCount    int                  `json:"application_rule_count"`
	OUICount                int                  `json:"oui_count"`
	DHCPRuleCount           int                  `json:"dhcp_rule_count"`
	Sources                 []BundleSource       `json:"sources,omitempty"`
	Licenses                []string             `json:"licenses,omitempty"`
	BackfillStatus          string               `json:"backfill_status,omitempty"`
	BackfillProcessed       int                  `json:"backfill_processed,omitempty"`
	DomainAvailable         bool                 `json:"domain_available"`
	BrandEligibleRuleCount  int                  `json:"brand_eligible_rule_count"`
	DomainSources           []DomainSourceStatus `json:"domain_sources,omitempty"`
	DomainRuleCount         int                  `json:"domain_rule_count"`
	DomainEcosystemCount    int                  `json:"domain_ecosystem_count"`
	DomainSourceVersion     string               `json:"domain_source_version,omitempty"`
	DomainBackfillStatus    string               `json:"domain_backfill_status,omitempty"`
	DomainBackfillProcessed int                  `json:"domain_backfill_processed,omitempty"`
	DomainBackfillLastError string               `json:"domain_backfill_last_error,omitempty"`
}

type Manager struct {
	mu           sync.RWMutex
	importMu     sync.Mutex
	dir          string
	client       *http.Client
	status       Status
	builtin      []Rule
	ouiURLs      []string
	uapCommitURL string
	uapRawURL    string
}

func NewManager(dir string) *Manager {
	var builtin []Rule
	_ = json.Unmarshal(embeddedRules, &builtin)
	manager := &Manager{
		dir:          dir,
		client:       &http.Client{Timeout: 30 * time.Second},
		status:       libraryStatus(defaultLibrary, Status{Version: EmbeddedVersion, Status: "ready", Source: "embedded", OfflineMode: true}),
		builtin:      builtin,
		ouiURLs:      []string{defaultIEEEOUIURL, defaultIEEEMAMURL, defaultIEEEMASURL},
		uapCommitURL: defaultUAPCommitURL,
		uapRawURL:    defaultUAPRawURL,
	}
	manager.loadCurrent()
	return manager
}

func (m *Manager) SetOffline(offline bool) {
	m.mu.Lock()
	m.status.OfflineMode = offline
	m.mu.Unlock()
}

func (m *Manager) Import(data []byte) (Status, error) { return m.ImportWithGuard(data, nil) }

func (m *Manager) ImportWithGuard(data []byte, check func() error) (Status, error) {
	m.importMu.Lock()
	defer m.importMu.Unlock()
	bundle, err := VerifyBundleBytes(data)
	if err != nil {
		return m.fail(err)
	}
	library, err := LoadWithDomainData(bundle.Manifest.Version, bundle.Files["oui.csv"], bundle.Files["device-rules.json"], bundle.Files["fingerbank-dhcp.json"], bundle.Files["brand-aliases.json"], bundle.Files["domain-signatures.json"])
	if err != nil {
		return m.fail(err)
	}
	current := m.Status()
	if current.Version == bundle.Manifest.Version && current.Checksum != "" && current.Checksum != bundleChecksum(bundle) {
		return m.fail(fmt.Errorf("rule version already exists with different content"))
	}
	if check != nil {
		if err := check(); err != nil {
			return m.Status(), err
		}
	}
	if err := m.activateBundle(bundle); err != nil {
		return m.fail(err)
	}
	routerRuleSet, err := LoadRouterRuleSet(bundle.Files["router-rules.json"])
	if err != nil {
		return m.fail(err)
	}
	if len(bundle.Files["application-signatures.json"]) > 0 {
		if err := setApplicationSignatures(bundle.Files["application-signatures.json"], bundle.Manifest.Version); err != nil {
			return m.fail(err)
		}
	}
	SetDefault(library)
	SetDefaultRouterRuleSet(routerRuleSet)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	m.mu.Lock()
	status := libraryStatus(library, Status{Version: bundle.Manifest.Version, Status: "ready", Source: "offline-bundle", Checksum: bundleChecksum(bundle), UpdatedAt: now, LastCheckedAt: now, OfflineMode: m.status.OfflineMode, Sources: bundle.Manifest.Sources, Licenses: bundleLicenses(bundle.Manifest), BackfillStatus: "pending", DomainBackfillStatus: domainBackfillInitialStatus(bundle.Manifest)})
	m.status = status
	m.mu.Unlock()
	m.persistStatus(status)
	return status, nil
}

func (m *Manager) activateBundle(bundle Bundle) error {
	if m.dir == "" {
		return nil
	}
	releases := filepath.Join(m.dir, "releases")
	if err := os.MkdirAll(releases, 0o750); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(releases, ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for name, data := range bundle.Files {
		path := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0o640); err != nil {
			return err
		}
	}
	manifestData, _ := json.MarshalIndent(bundle.Manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), manifestData, 0o640); err != nil {
		return err
	}
	release := filepath.Join(releases, safeVersion(bundle.Manifest.Version))
	if _, err := os.Stat(release); err == nil {
		release += "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	if err := os.Rename(stage, release); err != nil {
		return err
	}
	tempLink := filepath.Join(m.dir, ".current-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := os.Symlink(release, tempLink); err != nil {
		return err
	}
	if err := os.Rename(tempLink, filepath.Join(m.dir, "current")); err != nil {
		os.Remove(tempLink)
		return err
	}
	m.pruneReleases(releases, release)
	return nil
}

func (m *Manager) pruneReleases(dir, current string) {
	entries, _ := os.ReadDir(dir)
	type release struct {
		name string
		info os.FileInfo
	}
	items := []release{}
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			if info, err := entry.Info(); err == nil {
				items = append(items, release{entry.Name(), info})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].info.ModTime().After(items[j].info.ModTime()) })
	if len(items) <= 3 {
		return
	}
	for _, item := range items[3:] {
		path := filepath.Join(dir, item.name)
		if path != current {
			_ = os.RemoveAll(path)
		}
	}
}

func safeVersion(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, value)
}
func bundleChecksum(bundle Bundle) string {
	data, _ := json.Marshal(bundle.Manifest.Files)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func libraryStatus(library *Library, status Status) Status {
	status.ApplicationRuleCount = ApplicationRuleCount()
	if library != nil {
		status.RuleCount = len(library.rules)
		status.OUICount = len(library.ouis)
		status.DHCPRuleCount = 0
		status.DomainRuleCount = library.DomainRuleCount()
		status.DomainAvailable = status.DomainRuleCount > 0
		if status.DomainAvailable {
			status.DomainSourceVersion = library.Version()
		}
		status.DomainSources = library.DomainSourceStatus()
		status.BrandEligibleRuleCount = 0
		for _, rule := range library.domains {
			if rule.BrandEligible {
				status.BrandEligibleRuleCount++
			}
		}
		status.DomainEcosystemCount = library.DomainEcosystemCount()
		for _, items := range library.dhcp {
			status.DHCPRuleCount += len(items)
		}
	}
	status.RouterRuleCount = len(DefaultRouterRuleSet().Rules)
	for _, source := range status.Sources {
		if source.Name == "NextDNS native-tracking-domains" {
			status.DomainSourceVersion = source.Version
			break
		}
	}
	return status
}

func bundleLicenses(manifest BundleManifest) []string {
	result := []string{"Apache-2.0", "ODbL-1.0", "DbCL-1.0", "IEEE public registry"}
	for _, source := range manifest.Sources {
		if source.Name == "HaGeZi native trackers" {
			result = append(result, "GPL-3.0 (HaGeZi)")
		}
	}
	for _, source := range manifest.Sources {
		if source.Name == "NextDNS native-tracking-domains" {
			result = append(result, "MIT (NextDNS)")
		}
	}
	return result
}
func domainBackfillInitialStatus(manifest BundleManifest) string {
	if manifest.SchemaVersion == BundleSchemaVersionV2 || manifest.SchemaVersion == BundleSchemaVersionV3 || manifest.SchemaVersion == BundleSchemaVersionV4 || manifest.SchemaVersion == BundleSchemaVersionV5 {
		return "pending"
	}
	return "not_required"
}

func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Manager) SetBackfill(status string, processed int) {
	m.mu.Lock()
	m.status.BackfillStatus = status
	m.status.BackfillProcessed = processed
	current := m.status
	m.mu.Unlock()
	m.persistStatus(current)
}

func (m *Manager) SetDomainBackfill(status string, processed int) {
	m.mu.Lock()
	m.status.DomainBackfillStatus = status
	m.status.DomainBackfillProcessed = processed
	if status != "failed" {
		m.status.DomainBackfillLastError = ""
	}
	current := m.status
	m.mu.Unlock()
	m.persistStatus(current)
}

func (m *Manager) SetDomainBackfillFailure(processed int, err error) {
	m.mu.Lock()
	m.status.DomainBackfillStatus = "failed"
	m.status.DomainBackfillProcessed = processed
	if err != nil {
		m.status.DomainBackfillLastError = err.Error()
	}
	current := m.status
	m.mu.Unlock()
	m.persistStatus(current)
}

func (m *Manager) Start(ctx context.Context, interval time.Duration) {
	m.mu.RLock()
	offline := m.status.OfflineMode
	m.mu.RUnlock()
	if offline {
		return
	}
	if interval <= 0 {
		interval = 7 * 24 * time.Hour
	}
	go func() {
		timer := time.NewTimer(interval + time.Duration(time.Now().UnixNano()%int64(time.Hour)))
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				_, _ = m.Update(ctx)
				timer.Reset(interval + time.Duration(time.Now().UnixNano()%int64(time.Hour)))
			}
		}
	}()
}

func (m *Manager) Update(ctx context.Context) (Status, error) { return m.UpdateWithGuard(ctx, nil) }

func (m *Manager) UpdateWithGuard(ctx context.Context, check func() error) (Status, error) {
	m.mu.RLock()
	offline := m.status.OfflineMode
	m.mu.RUnlock()
	if offline {
		return m.fail(fmt.Errorf("offline_update_required: import a verified local device fingerprint bundle"))
	}
	m.setChecking()
	ouiParts := make([][]byte, 0, 3)
	for _, rawURL := range m.ouiURLs {
		data, err := m.download(ctx, rawURL, 32<<20)
		if err != nil {
			return m.fail(err)
		}
		ouiParts = append(ouiParts, data)
	}
	ouiData, err := mergeOUICSV(ouiParts)
	if err != nil {
		return m.fail(err)
	}
	commitData, err := m.download(ctx, m.uapCommitURL, 1<<20)
	if err != nil {
		return m.fail(err)
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(commitData, &commit); err != nil || len(commit.SHA) < 12 {
		return m.fail(fmt.Errorf("invalid uap-core commit response"))
	}
	uapData, err := m.download(ctx, fmt.Sprintf(m.uapRawURL, commit.SHA), 16<<20)
	if err != nil {
		return m.fail(err)
	}
	uapRules, err := RulesFromUAP(uapData)
	if err != nil {
		return m.fail(err)
	}
	rulesData, err := EncodeRules(append(append([]Rule{}, m.builtin...), uapRules...))
	if err != nil {
		return m.fail(err)
	}
	checksumBytes := sha256.Sum256(append(append([]byte{}, ouiData...), rulesData...))
	checksum := hex.EncodeToString(checksumBytes[:])
	version := "ieee+uap-" + commit.SHA[:12]
	library, err := Load(version, ouiData, rulesData)
	if err != nil {
		return m.fail(err)
	}
	if err := ctx.Err(); err != nil {
		return m.Status(), err
	}
	if check != nil {
		if err := check(); err != nil {
			return m.Status(), err
		}
	}
	if err := m.activate(ouiData, rulesData); err != nil {
		return m.fail(err)
	}
	SetDefault(library)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	m.mu.Lock()
	m.status = Status{Version: version, Status: "ready", Source: "ieee+uap-core", Checksum: checksum, UpdatedAt: now, LastCheckedAt: now}
	status := m.status
	m.mu.Unlock()
	m.persistStatus(status)
	return status, nil
}

func (m *Manager) download(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxy-sentinel-device-library/1")
	response, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", rawURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", rawURL, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("download %s exceeds size limit", rawURL)
	}
	return data, nil
}

func (m *Manager) activate(ouiData, rulesData []byte) error {
	if m.dir == "" {
		return nil
	}
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		data []byte
	}{{"oui.csv", ouiData}, {"device-rules.json", rulesData}} {
		path := filepath.Join(m.dir, item.name)
		if current, err := os.ReadFile(path); err == nil {
			_ = os.Rename(path+".bak", path+".bak.2")
			_ = os.WriteFile(path+".bak", current, 0o640)
		}
		temp, err := os.CreateTemp(m.dir, item.name+"-*")
		if err != nil {
			return err
		}
		tempName := temp.Name()
		if _, err := temp.Write(item.data); err != nil {
			temp.Close()
			os.Remove(tempName)
			return err
		}
		if err := temp.Close(); err != nil {
			os.Remove(tempName)
			return err
		}
		if err := os.Chmod(tempName, 0o640); err != nil {
			os.Remove(tempName)
			return err
		}
		if err := os.Rename(tempName, path); err != nil {
			os.Remove(tempName)
			return err
		}
	}
	return nil
}

func (m *Manager) loadCurrent() {
	if m.dir == "" {
		return
	}
	base := m.dir
	if target, err := filepath.EvalSymlinks(filepath.Join(m.dir, "current")); err == nil {
		base = target
	}
	ouiData, ouiErr := os.ReadFile(filepath.Join(base, "oui.csv"))
	rulesData, rulesErr := os.ReadFile(filepath.Join(m.dir, "device-rules.json"))
	if base != m.dir {
		rulesData, rulesErr = os.ReadFile(filepath.Join(base, "device-rules.json"))
	}
	if ouiErr != nil || rulesErr != nil {
		return
	}
	statusData, _ := os.ReadFile(filepath.Join(m.dir, "status.json"))
	status := m.status
	_ = json.Unmarshal(statusData, &status)
	fingerbankData, _ := os.ReadFile(filepath.Join(base, "fingerbank-dhcp.json"))
	if len(fingerbankData) == 0 {
		fingerbankData = []byte("[]")
	}
	aliasesData, _ := os.ReadFile(filepath.Join(base, "brand-aliases.json"))
	if len(aliasesData) == 0 {
		aliasesData = embeddedBrandAliases
	}
	domainData, _ := os.ReadFile(filepath.Join(base, "domain-signatures.json"))
	applicationData, _ := os.ReadFile(filepath.Join(base, "application-signatures.json"))
	routerData, _ := os.ReadFile(filepath.Join(base, "router-rules.json"))
	library, err := LoadWithDomainData(status.Version, ouiData, rulesData, fingerbankData, aliasesData, domainData)
	if err != nil {
		m.status.Status = "degraded"
		m.status.LastError = "load domain/device rules: " + err.Error()
		return
	}
	SetDefault(library)
	if loaded, loadErr := LoadRouterRuleSet(routerData); loadErr == nil {
		SetDefaultRouterRuleSet(loaded)
	}
	if len(applicationData) > 0 {
		_ = setApplicationSignatures(applicationData, status.Version)
	}
	m.status = libraryStatus(library, status)
}

func (m *Manager) setChecking() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Status = "checking"
	m.status.LastCheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	m.status.LastError = ""
}

func (m *Manager) fail(err error) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Status = "degraded"
	m.status.LastCheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	m.status.LastError = err.Error()
	return m.status, err
}

func (m *Manager) persistStatus(status Status) {
	if m.dir == "" {
		return
	}
	data, _ := json.MarshalIndent(status, "", "  ")
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		return
	}
	temp, err := os.CreateTemp(m.dir, ".status-*.json")
	if err != nil {
		return
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(data); err != nil || temp.Sync() != nil || temp.Close() != nil || os.Chmod(name, 0o640) != nil {
		_ = temp.Close()
		return
	}
	_ = os.Rename(name, filepath.Join(m.dir, "status.json"))
}

func mergeOUICSV(parts [][]byte) ([]byte, error) {
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	if err := writer.Write([]string{"Assignment", "Organization Name"}); err != nil {
		return nil, err
	}
	for _, part := range parts {
		reader := csv.NewReader(bytes.NewReader(part))
		reader.FieldsPerRecord = -1
		records, err := reader.ReadAll()
		if err != nil || len(records) < 2 {
			return nil, fmt.Errorf("invalid IEEE OUI CSV")
		}
		assignmentIndex, organizationIndex := -1, -1
		for index, value := range records[0] {
			switch value {
			case "Assignment":
				assignmentIndex = index
			case "Organization Name":
				organizationIndex = index
			}
		}
		if assignmentIndex < 0 || organizationIndex < 0 {
			return nil, fmt.Errorf("invalid IEEE OUI CSV headers")
		}
		for _, record := range records[1:] {
			if assignmentIndex >= len(record) || organizationIndex >= len(record) {
				continue
			}
			if err := writer.Write([]string{record[assignmentIndex], record[organizationIndex]}); err != nil {
				return nil, err
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
