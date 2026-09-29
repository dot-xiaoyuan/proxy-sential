package appdomain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LibraryStatus struct {
	Version     string   `json:"version"`
	Versions    []string `json:"versions"`
	RuleCount   int      `json:"rule_count"`
	ActivatedAt string   `json:"activated_at"`
}
type Manager struct {
	mu     sync.RWMutex
	dir    string
	bundle *Bundle
	status LibraryStatus
}

func OpenManager(dir string) (*Manager, error) {
	m := &Manager{dir: dir, status: LibraryStatus{Versions: []string{}}}
	data, err := os.ReadFile(filepath.Join(dir, "active.json"))
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &m.status); err != nil {
		return nil, err
	}
	if !safeVersion.MatchString(m.status.Version) {
		return nil, fmt.Errorf("invalid saved version")
	}
	raw, err := os.ReadFile(filepath.Join(dir, m.status.Version+".tar.gz"))
	if err != nil {
		return nil, err
	}
	m.bundle, err = Verify(raw)
	return m, err
}
func (m *Manager) Snapshot() (*Bundle, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundle, m.status.ActivatedAt
}
func (m *Manager) Status() LibraryStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.status
	s.Versions = append([]string{}, s.Versions...)
	return s
}
func (m *Manager) Import(raw []byte) error { return m.ImportWithGuard(raw, nil) }

func (m *Manager) ImportWithGuard(raw []byte, check func() error) error {
	b, err := Verify(raw)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := filepath.Join(m.dir, b.Manifest.Version+".tar.gz")
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("version already exists; use rollback")
	} else if !os.IsNotExist(err) {
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	if err := atomicJSONBytes(p, raw); err != nil {
		return err
	}
	if err := m.activate(b); err != nil {
		_ = os.Remove(p)
		return err
	}
	return nil
}
func (m *Manager) Rollback(v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	for _, existing := range m.status.Versions {
		if v == existing {
			found = true
		}
	}
	if !safeVersion.MatchString(v) || !found {
		return fmt.Errorf("version is not retained")
	}
	raw, err := os.ReadFile(filepath.Join(m.dir, v+".tar.gz"))
	if err != nil {
		return err
	}
	b, err := Verify(raw)
	if err != nil {
		return err
	}
	return m.activate(b)
}
func (m *Manager) activate(b *Bundle) error {
	versions := []string{b.Manifest.Version}
	for _, v := range m.status.Versions {
		if v != b.Manifest.Version {
			versions = append(versions, v)
		}
	}
	old := append([]string{}, versions...)
	if len(versions) > 3 {
		versions = versions[:3]
	}
	status := LibraryStatus{b.Manifest.Version, versions, len(b.Rules), time.Now().UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if err = atomicJSONBytes(filepath.Join(m.dir, "active.json"), data); err != nil {
		return err
	}
	m.status = status
	m.bundle = b
	for _, v := range old {
		keep := false
		for _, k := range versions {
			if v == k {
				keep = true
			}
		}
		if !keep {
			_ = os.Remove(filepath.Join(m.dir, v+".tar.gz"))
		}
	}
	return nil
}
func atomicJSONBytes(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), p); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (m *Manager) matchesCurrentBundle(raw []byte) bool {
	b, err := Verify(raw)
	if err != nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status.Version != b.Manifest.Version {
		return false
	}
	stored, err := os.ReadFile(filepath.Join(m.dir, b.Manifest.Version+".tar.gz"))
	return err == nil && bytes.Equal(stored, raw)
}
