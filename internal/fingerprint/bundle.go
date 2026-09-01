package fingerprint

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	BundleSchemaVersion = "device-fingerprint-bundle/v1"
	MaxBundleBytes      = 32 << 20
	MaxBundleContent    = 128 << 20
	fingerbankURL       = "https://raw.githubusercontent.com/karottc/fingerbank/master/dhcp_fingerprints.conf"
	odblURL             = "https://opendatacommons.org/licenses/odbl/1-0/"
	dbclURL             = "https://opendatacommons.org/licenses/dbcl/1-0/"
)

type BundleSource struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
	License string `json:"license"`
}

type BundleFile struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type BundleManifest struct {
	SchemaVersion string                `json:"schema_version"`
	Version       string                `json:"version"`
	CreatedAt     string                `json:"created_at"`
	Sources       []BundleSource        `json:"sources"`
	Files         map[string]BundleFile `json:"files"`
}

type Bundle struct {
	Manifest BundleManifest
	Files    map[string][]byte
}

type BuildOptions struct {
	HTTPClient    *http.Client
	Now           func() time.Time
	OUIURLs       []string
	UAPCommitURL  string
	UAPRawURL     string
	UAPSHA        string
	FingerbankURL string
	ODbLURL       string
	DbCLURL       string
}

func BuildOfflineBundle(ctx context.Context, output string, options BuildOptions) (BundleManifest, error) {
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	ouiURLs := options.OUIURLs
	if len(ouiURLs) == 0 {
		ouiURLs = []string{defaultIEEEOUIURL, defaultIEEEMAMURL, defaultIEEEMASURL}
	}
	uapCommitURL := fallback(options.UAPCommitURL, defaultUAPCommitURL)
	uapRawURL := fallback(options.UAPRawURL, defaultUAPRawURL)
	fbURL := fallback(options.FingerbankURL, fingerbankURL)
	licenseURL := fallback(options.ODbLURL, odblURL)
	dbLicenseURL := fallback(options.DbCLURL, dbclURL)
	ouiParts := make([][]byte, 0, len(ouiURLs))
	for _, rawURL := range ouiURLs {
		data, err := downloadURL(ctx, client, rawURL, 32<<20)
		if err != nil {
			return BundleManifest{}, err
		}
		ouiParts = append(ouiParts, data)
	}
	ouiData, err := mergeOUICSV(ouiParts)
	if err != nil {
		return BundleManifest{}, err
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	commit.SHA = strings.TrimSpace(options.UAPSHA)
	if commit.SHA == "" {
		commitData, err := downloadURL(ctx, client, uapCommitURL, 1<<20)
		if err != nil {
			return BundleManifest{}, err
		}
		if json.Unmarshal(commitData, &commit) != nil {
			return BundleManifest{}, fmt.Errorf("invalid uap-core commit response")
		}
	}
	if len(commit.SHA) < 12 || strings.IndexFunc(commit.SHA, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') }) >= 0 {
		return BundleManifest{}, fmt.Errorf("invalid uap-core commit SHA")
	}
	uapData, err := downloadURL(ctx, client, fmt.Sprintf(uapRawURL, commit.SHA), 16<<20)
	if err != nil {
		return BundleManifest{}, err
	}
	uapRules, err := RulesFromUAP(uapData)
	if err != nil {
		return BundleManifest{}, err
	}
	var builtin []Rule
	if err := json.Unmarshal(embeddedRules, &builtin); err != nil {
		return BundleManifest{}, err
	}
	rulesData, err := EncodeRules(append(builtin, uapRules...))
	if err != nil {
		return BundleManifest{}, err
	}
	fingerbankRaw, err := downloadURL(ctx, client, fbURL, 8<<20)
	if err != nil {
		return BundleManifest{}, err
	}
	fingerbankData, err := FingerbankFromLegacy(fingerbankRaw)
	if err != nil {
		return BundleManifest{}, err
	}
	odbl, err := downloadURL(ctx, client, licenseURL, 1<<20)
	if err != nil {
		return BundleManifest{}, err
	}
	dbcl, err := downloadURL(ctx, client, dbLicenseURL, 1<<20)
	if err != nil {
		return BundleManifest{}, err
	}
	files := map[string][]byte{
		"oui.csv": ouiData, "device-rules.json": rulesData, "fingerbank-dhcp.json": fingerbankData,
		"brand-aliases.json": embeddedBrandAliases, "licenses/ODbL-1.0.html": odbl, "licenses/DbCL-1.0.html": dbcl,
		"licenses/NOTICE.txt": []byte("Fingerbank public snapshot is used under ODbL-1.0 and its individual contents under DbCL-1.0. The snapshot is historical and is used only as auxiliary DHCP evidence.\n"),
	}
	createdAt := now().UTC()
	manifest := BundleManifest{SchemaVersion: BundleSchemaVersion, Version: "offline-" + createdAt.Format("20060102") + "-" + commit.SHA[:12], CreatedAt: createdAt.Format(time.RFC3339Nano), Sources: []BundleSource{
		{Name: "IEEE MA-L/MA-M/MA-S", Version: createdAt.Format("2006-01-02"), URL: "https://standards-oui.ieee.org/", License: "IEEE public registry"},
		{Name: "uap-core", Version: commit.SHA, URL: fmt.Sprintf(uapRawURL, commit.SHA), License: "Apache-2.0"},
		{Name: "Fingerbank public snapshot", Version: "6.8.2-20140609", URL: fbURL, License: "ODbL-1.0/DbCL-1.0"},
	}, Files: map[string]BundleFile{}}
	for name, data := range files {
		manifest.Files[name] = bundleFile(data)
	}
	data, err := encodeBundle(manifest, files)
	if err != nil {
		return BundleManifest{}, err
	}
	if len(data) > MaxBundleBytes {
		return BundleManifest{}, fmt.Errorf("bundle exceeds %d bytes", MaxBundleBytes)
	}
	if err := os.WriteFile(output, data, 0o640); err != nil {
		return BundleManifest{}, err
	}
	return manifest, nil
}

func VerifyBundleBytes(data []byte) (Bundle, error) {
	if len(data) == 0 || len(data) > MaxBundleBytes {
		return Bundle{}, fmt.Errorf("bundle size must be between 1 and %d bytes", MaxBundleBytes)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Bundle{}, fmt.Errorf("open bundle gzip: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	files := map[string][]byte{}
	total := int64(0)
	allowed := map[string]bool{"manifest.json": true, "oui.csv": true, "device-rules.json": true, "fingerbank-dhcp.json": true, "brand-aliases.json": true, "licenses/ODbL-1.0.html": true, "licenses/DbCL-1.0.html": true, "licenses/NOTICE.txt": true}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Bundle{}, fmt.Errorf("read bundle: %w", err)
		}
		name := filepath.ToSlash(filepath.Clean(header.Name))
		if header.Typeflag != tar.TypeReg || !allowed[name] || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			return Bundle{}, fmt.Errorf("bundle contains unsupported entry %q", header.Name)
		}
		if _, exists := files[name]; exists {
			return Bundle{}, fmt.Errorf("bundle contains duplicate entry %q", name)
		}
		if header.Size < 0 || total+header.Size > MaxBundleContent {
			return Bundle{}, fmt.Errorf("bundle content exceeds %d bytes", MaxBundleContent)
		}
		payload, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(payload)) != header.Size {
			return Bundle{}, fmt.Errorf("read bundle entry %q", name)
		}
		total += header.Size
		files[name] = payload
	}
	required := []string{"manifest.json", "oui.csv", "device-rules.json", "fingerbank-dhcp.json", "brand-aliases.json", "licenses/ODbL-1.0.html", "licenses/DbCL-1.0.html", "licenses/NOTICE.txt"}
	for _, name := range required {
		if len(files[name]) == 0 {
			return Bundle{}, fmt.Errorf("bundle is missing %q", name)
		}
	}
	var manifest BundleManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		return Bundle{}, fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.SchemaVersion != BundleSchemaVersion || manifest.Version == "" {
		return Bundle{}, fmt.Errorf("unsupported bundle manifest")
	}
	for _, name := range required[1:] {
		expected, ok := manifest.Files[name]
		if !ok || expected != bundleFile(files[name]) {
			return Bundle{}, fmt.Errorf("bundle checksum mismatch for %q", name)
		}
	}
	if _, err := LoadWithData(manifest.Version, files["oui.csv"], files["device-rules.json"], files["fingerbank-dhcp.json"], files["brand-aliases.json"]); err != nil {
		return Bundle{}, err
	}
	return Bundle{Manifest: manifest, Files: files}, nil
}

func VerifyBundleFile(path string) (Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, err
	}
	return VerifyBundleBytes(data)
}

func encodeBundle(manifest BundleManifest, files map[string][]byte) ([]byte, error) {
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	all := make(map[string][]byte, len(files)+1)
	for name, data := range files {
		all[name] = data
	}
	all["manifest.json"] = manifestData
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gz)
	for _, name := range names {
		data := all[name]
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(data)), ModTime: time.Unix(0, 0)}); err != nil {
			return nil, err
		}
		if _, err := tarWriter.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func bundleFile(data []byte) BundleFile {
	sum := sha256.Sum256(data)
	return BundleFile{Size: len(data), SHA256: hex.EncodeToString(sum[:])}
}
func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}
func downloadURL(ctx context.Context, client *http.Client, rawURL string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxy-sentinel-device-library/1")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", rawURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", rawURL, res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("download %s exceeds size limit", rawURL)
	}
	return data, nil
}
