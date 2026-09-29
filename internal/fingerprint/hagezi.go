package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func buildHaGeZi(ctx context.Context, client *http.Client, options BuildOptions) ([]DomainSignature, BundleSource, map[string][]byte, error) {
	sha := options.HaGeZiSHA
	raw := fallback(options.HaGeZiRawURL, "https://raw.githubusercontent.com/hagezi/dns-blocklists/%s/%s")
	if sha == "" {
		data, err := downloadURL(ctx, client, fallback(options.HaGeZiCommitURL, "https://api.github.com/repos/hagezi/dns-blocklists/commits/main"), 1<<20)
		if err != nil {
			return nil, BundleSource{}, nil, err
		}
		var commit struct {
			SHA string `json:"sha"`
		}
		if err = json.Unmarshal(data, &commit); err != nil {
			return nil, BundleSource{}, nil, err
		}
		sha = commit.SHA
	}
	if !validCommitSHA(sha) {
		return nil, BundleSource{}, nil, fmt.Errorf("invalid HaGeZi commit SHA")
	}
	rules := []DomainSignature{}
	snapshots := map[string]string{}
	for _, entry := range []struct{ file, ecosystem string }{{"apple", "Apple"}, {"huawei", "Huawei"}, {"samsung", "Samsung"}, {"xiaomi", "Xiaomi"}, {"vivo", "Vivo"}, {"oppo-realme", "OPPO/Realme"}} {
		path := "wildcard/native." + entry.file + "-onlydomains.txt"
		url := fmt.Sprintf(raw, sha, path)
		data, err := downloadURL(ctx, client, url, 4<<20)
		if err != nil {
			return nil, BundleSource{}, nil, err
		}
		snapshots[path] = string(data)
		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			domain := strings.TrimSpace(line)
			if domain == "" || strings.HasPrefix(domain, "#") || strings.HasPrefix(domain, "!") {
				continue
			}
			normalized, err := normalizeDomain(domain)
			if err != nil || !strings.Contains(normalized, ".") {
				return nil, BundleSource{}, nil, fmt.Errorf("invalid HaGeZi domain in %s: %q", path, domain)
			}
			rules = append(rules, DomainSignature{Domain: normalized, MatchType: DomainMatchSubdomain, Ecosystem: entry.ecosystem, Category: "telemetry", Confidence: .55, Source: "HaGeZi", SourceURL: url, SourceVersion: sha, Purpose: "原生遥测生态线索"})
			count++
		}
		if count == 0 {
			return nil, BundleSource{}, nil, fmt.Errorf("empty HaGeZi category: %s", entry.file)
		}
	}
	license, err := downloadURL(ctx, client, fmt.Sprintf(raw, sha, "LICENSE"), 1<<20)
	if err != nil {
		return nil, BundleSource{}, nil, err
	}
	data, _ := json.MarshalIndent(snapshots, "", "  ")
	return rules, BundleSource{Name: "HaGeZi native trackers", Version: sha, URL: fmt.Sprintf(raw, sha, "wildcard/"), License: "GPL-3.0"}, map[string][]byte{"licenses/HaGeZi-GPL-3.0.txt": license, "sources/hagezi.json": data}, nil
}

func writeBundleAtomic(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".fingerprint-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0o640); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}
