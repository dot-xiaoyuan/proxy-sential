// Package appdomain classifies standard domain observations independently of risk scoring.
package appdomain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const SchemaVersion = "application-domain-bundle/v1"
const MaxBundleBytes = 32 << 20
const MaxContentBytes = 128 << 20

var safeVersion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$`)

type Target struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Vendor   string   `json:"vendor,omitempty"`
	Aliases  []string `json:"aliases,omitempty"`
}
type Catalog struct {
	Applications    []Target `json:"applications"`
	Ecosystems      []Target `json:"ecosystems"`
	Infrastructures []Target `json:"infrastructures"`
}
type Rule struct {
	ID            string  `json:"rule_id"`
	Domain        string  `json:"domain"`
	MatchType     string  `json:"match_type"`
	TargetType    string  `json:"target_type"`
	TargetID      string  `json:"target_id"`
	Confidence    float64 `json:"confidence"`
	Source        string  `json:"source"`
	SourceVersion string  `json:"source_version"`
}
type Source struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}
type File struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	SchemaVersion string          `json:"schema_version"`
	Version       string          `json:"version"`
	CreatedAt     string          `json:"created_at"`
	Sources       []Source        `json:"sources"`
	Files         map[string]File `json:"files"`
}
type Bundle struct {
	Manifest Manifest
	Catalog  Catalog
	Rules    []Rule
	index    map[string]Rule
	targets  map[string]Target
}
type Match struct {
	RuleID        string  `json:"rule_id,omitempty"`
	TargetID      string  `json:"target_id,omitempty"`
	TargetType    string  `json:"target_type,omitempty"`
	Name          string  `json:"name,omitempty"`
	Category      string  `json:"category,omitempty"`
	Confidence    float64 `json:"confidence"`
	Source        string  `json:"source,omitempty"`
	SourceVersion string  `json:"source_version,omitempty"`
}

func NormalizeDomain(raw string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	ascii, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return "", err
	}
	d = ascii
	if len(d) > 253 || !strings.Contains(d, ".") {
		return "", fmt.Errorf("invalid domain %q", raw)
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", fmt.Errorf("IP is not a domain")
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid domain character")
			}
		}
	}
	suffix, _ := publicsuffix.PublicSuffix(d)
	if suffix == d {
		return "", fmt.Errorf("public suffix cannot be a rule")
	}
	return d, nil
}
func (b *Bundle) validate() error {
	if b.Manifest.SchemaVersion != SchemaVersion || !safeVersion.MatchString(b.Manifest.Version) {
		return fmt.Errorf("unsupported schema or invalid version")
	}
	if _, err := time.Parse(time.RFC3339Nano, b.Manifest.CreatedAt); err != nil {
		return err
	}
	sources := map[string]bool{}
	for _, s := range b.Manifest.Sources {
		if s.Name == "" || s.Version == "" || s.License == "" {
			return fmt.Errorf("source metadata required")
		}
		sources[s.Name+"\x00"+s.Version] = true
	}
	b.targets = map[string]Target{}
	for kind, ts := range map[string][]Target{"application": b.Catalog.Applications, "ecosystem": b.Catalog.Ecosystems, "infrastructure": b.Catalog.Infrastructures} {
		for _, t := range ts {
			key := kind + ":" + t.ID
			if t.ID == "" || t.Name == "" || t.Category == "" {
				return fmt.Errorf("target metadata required")
			}
			if _, ok := b.targets[key]; ok {
				return fmt.Errorf("duplicate target %s", key)
			}
			b.targets[key] = t
		}
	}
	b.index = map[string]Rule{}
	ids := map[string]bool{}
	for i, r := range b.Rules {
		d, err := NormalizeDomain(r.Domain)
		if err != nil {
			return err
		}
		r.Domain = d
		b.Rules[i] = r
		if r.ID == "" || ids[r.ID] || r.Confidence < 0 || r.Confidence > 1 {
			return fmt.Errorf("invalid rule %s", r.ID)
		}
		ids[r.ID] = true
		if r.MatchType != "exact" && r.MatchType != "suffix" {
			return fmt.Errorf("unsupported match type")
		}
		if _, ok := b.targets[r.TargetType+":"+r.TargetID]; !ok {
			return fmt.Errorf("missing target")
		}
		if !sources[r.Source+"\x00"+r.SourceVersion] {
			return fmt.Errorf("undeclared source")
		}
		key := r.MatchType + ":" + d
		if _, ok := b.index[key]; ok {
			return fmt.Errorf("duplicate or conflicting rule %s", key)
		}
		b.index[key] = r
	}
	if len(b.Rules) == 0 {
		return fmt.Errorf("empty rule set")
	}
	return nil
}
func (b *Bundle) Match(host string) Match {
	if b == nil {
		return Match{}
	}
	d, err := NormalizeDomain(host)
	if err != nil {
		return Match{}
	}
	original := d
	for {
		types := []string{"suffix"}
		if d == original {
			types = []string{"exact", "suffix"}
		}
		for _, kind := range types {
			if r, ok := b.index[kind+":"+d]; ok {
				t := b.targets[r.TargetType+":"+r.TargetID]
				return Match{r.ID, r.TargetID, r.TargetType, t.Name, t.Category, r.Confidence, r.Source, r.SourceVersion}
			}
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return Match{}
}
func Verify(raw []byte) (*Bundle, error) {
	if len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("compressed bundle too large")
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, MaxContentBytes+1))
	files := map[string][]byte{}
	total := int64(0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg || path.Clean(h.Name) != h.Name || strings.Contains(h.Name, "\\") || strings.HasPrefix(h.Name, "/") || strings.HasPrefix(h.Name, "../") {
			return nil, fmt.Errorf("unsafe bundle entry")
		}
		if h.Name != "manifest.json" && h.Name != "applications.json" && h.Name != "domain-rules.json" && !(strings.HasPrefix(h.Name, "licenses/") && path.Base(h.Name) != ".") {
			return nil, fmt.Errorf("unexpected file %s", h.Name)
		}
		if _, ok := files[h.Name]; ok {
			return nil, fmt.Errorf("duplicate file")
		}
		total += h.Size
		if h.Size < 0 || total > MaxContentBytes {
			return nil, fmt.Errorf("bundle content too large")
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[h.Name] = data
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(gz, MaxContentBytes+1)); err != nil {
		return nil, err
	}
	b := &Bundle{}
	if err := json.Unmarshal(files["manifest.json"], &b.Manifest); err != nil {
		return nil, err
	}
	if len(b.Manifest.Files) != len(files)-1 {
		return nil, fmt.Errorf("manifest file list mismatch")
	}
	licenses := 0
	for name, data := range files {
		if name == "manifest.json" {
			continue
		}
		f, ok := b.Manifest.Files[name]
		sum := sha256.Sum256(data)
		if !ok || f.Size != len(data) || f.SHA256 != hex.EncodeToString(sum[:]) {
			return nil, fmt.Errorf("checksum mismatch: %s", name)
		}
		if strings.HasPrefix(name, "licenses/") && len(data) > 0 {
			licenses++
		}
	}
	if licenses == 0 {
		return nil, fmt.Errorf("license text required")
	}
	if err := json.Unmarshal(files["applications.json"], &b.Catalog); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(files["domain-rules.json"], &b.Rules); err != nil {
		return nil, err
	}
	return b, b.validate()
}

// Build serializes already reviewed data. Approval is enforced by the producer workflow.
func Build(version string, c Catalog, rules []Rule, sources []Source, licenses map[string][]byte, now time.Time) ([]byte, error) {
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	files := map[string][]byte{}
	for k, v := range licenses {
		files[k] = v
	}
	files["applications.json"], _ = json.Marshal(c)
	files["domain-rules.json"], _ = json.Marshal(rules)
	m := Manifest{SchemaVersion, version, now.UTC().Format(time.RFC3339Nano), sources, map[string]File{}}
	for k, v := range files {
		sum := sha256.Sum256(v)
		m.Files[k] = File{len(v), hex.EncodeToString(sum[:])}
	}
	files["manifest.json"], _ = json.Marshal(m)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := []string{}
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := tw.WriteHeader(&tar.Header{Name: k, Mode: 0600, Size: int64(len(files[k]))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(files[k]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if _, err := Verify(buf.Bytes()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// featurelib-new identifies provenance by id; older Sentinel v1 bundles used name.
// Both forms refer to the same rule source key and remain readable.
func (s *Source) UnmarshalJSON(raw []byte) error {
	var v struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
		License string `json:"license"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if v.ID != "" && v.Name != "" && v.ID != v.Name {
		return fmt.Errorf("conflicting source id and name")
	}
	s.Name = v.Name
	if s.Name == "" {
		s.Name = v.ID
	}
	s.Version = v.Version
	s.License = v.License
	return nil
}
