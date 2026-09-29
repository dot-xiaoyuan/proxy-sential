package appdomain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultUpdateURL = "http://192.168.0.30:8081"

type RuntimeConfig struct {
	HistoryIntervalMS    int    `json:"history_interval_ms"`
	CredentialConfigured bool   `json:"credential_configured"`
	Enabled              bool   `json:"enabled"`
	UpdateURL            string `json:"update_url"`
	LastPullAt           string `json:"last_pull_at,omitempty"`
	LastPullError        string `json:"last_pull_error,omitempty"`
}

func OpenServiceWithDefault(dir string, source EventSource, enabled bool) (*Service, error) {
	s, err := OpenService(dir, source)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if os.IsNotExist(err) {
		s.config.Enabled = enabled
		s.config.UpdateURL = DefaultUpdateURL
		s.config.CredentialConfigured = s.savedCredential(s.config.UpdateURL) != ""
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &s.config); err != nil {
		return nil, err
	}
	if s.config.UpdateURL == "" {
		s.config.UpdateURL = DefaultUpdateURL
	}
	s.config.CredentialConfigured = s.savedCredential(s.config.UpdateURL) != ""
	return s, nil
}
func (s *Service) Configure(c RuntimeConfig) error {
	if c.HistoryIntervalMS == 0 {
		s.mu.RLock()
		c.HistoryIntervalMS = s.config.HistoryIntervalMS
		s.mu.RUnlock()
		if c.HistoryIntervalMS == 0 {
			c.HistoryIntervalMS = 1000
		}
	}
	if c.HistoryIntervalMS < 1000 || c.HistoryIntervalMS > 60000 {
		return fmt.Errorf("history interval must be 1000..60000 ms")
	}
	s.pull.Lock()
	defer s.pull.Unlock()
	c.UpdateURL = strings.TrimSpace(c.UpdateURL)
	if c.UpdateURL != "" {
		u, err := url.Parse(c.UpdateURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
			return fmt.Errorf("更新地址须为 HTTP(S) 下载地址，不含账号、查询参数或片段")
		}
	}
	s.work.Lock()
	defer s.work.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	c.LastPullAt = s.config.LastPullAt
	c.LastPullError = s.config.LastPullError
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err = atomicJSONBytes(filepath.Join(s.dir, "config.json"), raw); err != nil {
		return err
	}
	c.CredentialConfigured = s.savedCredential(c.UpdateURL) != ""
	s.config = c
	s.notify()
	return nil
}
func (s *Service) Pull(ctx context.Context) error { return s.PullWithToken(ctx, "") }
func (s *Service) PullWithToken(ctx context.Context, token string) error {
	return s.PullWithGuard(ctx, token, nil)
}

func (s *Service) PullWithGuard(ctx context.Context, token string, check func() error) (resultErr error) {
	s.pull.Lock()
	defer s.pull.Unlock()
	s.mu.RLock()
	address := s.config.UpdateURL
	s.mu.RUnlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.config.LastPullAt = time.Now().UTC().Format(time.RFC3339Nano)
		s.config.LastPullError = ""
		if resultErr != nil {
			s.config.LastPullError = resultErr.Error()
		}
		raw, _ := json.Marshal(s.config)
		if err := atomicJSONBytes(filepath.Join(s.dir, "config.json"), raw); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	if token == "" {
		token = s.savedCredential(address)
	}
	if address == "" {
		return fmt.Errorf("请先保存应用特征包下载地址")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("不允许重定向，请配置最终服务地址")
	}}
	fetch := func(address string, limit int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return nil, fmt.Errorf("无效更新地址")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("下载失败，请检查地址、连通性或超时")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("特征库下载返回 HTTP %d", resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, fmt.Errorf("读取特征库响应失败")
		}
		if int64(len(raw)) > limit {
			return nil, fmt.Errorf("特征库响应超过大小限制")
		}
		return raw, nil
	}
	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("无效更新地址")
	}
	var expected *Release
	if u.Path == "" || u.Path == "/" {
		base := strings.TrimRight(address, "/") + "/api/features/application-domain/bundles"
		data, err := fetch(base+"/index", 4<<20)
		if err != nil {
			return err
		}
		release, err := selectRelease(data)
		if err != nil {
			return err
		}
		expected = &release
		address = base + "/" + url.PathEscape(release.Version) + "/download"
	}
	raw, err := fetch(address, MaxBundleBytes)
	if err != nil {
		return err
	}
	b, err := Verify(raw)
	if err != nil {
		return err
	}
	if expected != nil {
		sum := sha256.Sum256(raw)
		created, _ := time.Parse(time.RFC3339Nano, b.Manifest.CreatedAt)
		indexed, _ := time.Parse(time.RFC3339Nano, expected.CreatedAt)
		if b.Manifest.Version != expected.Version || hex.EncodeToString(sum[:]) != strings.ToLower(expected.SHA256) || len(raw) != expected.Size || len(b.Rules) != expected.RuleCount || len(b.Catalog.Applications) != expected.ApplicationCount || !created.Equal(indexed) {
			return fmt.Errorf("下载包与发布索引的版本、校验和、时间或数量不一致")
		}
	}
	current, _ := s.Library.Snapshot()
	if current != nil && current.Manifest.Version == b.Manifest.Version {
		// A repeated fetch is successful only when immutable contents agree.
		previous, err := os.ReadFile(filepath.Join(s.Library.dir, b.Manifest.Version+".tar.gz"))
		if err != nil {
			return err
		}
		if string(previous) != string(raw) {
			return fmt.Errorf("同版本包内容发生变化，拒绝更新")
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.ChangeLibraryWithGuard(raw, "", check)
}

// Credentials are stored separately with mode 0600 and never returned in status.
// Binding to origin prevents forwarding a saved credential after changing servers.
func (s *Service) savedCredential(address string) string {
	var saved struct {
		Token  string `json:"token"`
		Origin string `json:"origin"`
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "download-credential.json"))
	if err != nil {
		return ""
	}
	if json.Unmarshal(raw, &saved) != nil {
		return ""
	}
	u, err := url.Parse(address)
	if err != nil || saved.Origin != u.Scheme+"://"+u.Host {
		return ""
	}
	return saved.Token
}
func (s *Service) SaveCredential(token string) error {
	s.pull.Lock()
	defer s.pull.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	if !strings.HasPrefix(token, "fld_") || len(token) != 68 {
		return fmt.Errorf("请使用特征库创建的专用下载凭证")
	}
	u, err := url.Parse(s.config.UpdateURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("请先保存服务地址")
	}
	raw, _ := json.Marshal(map[string]string{"token": token, "origin": u.Scheme + "://" + u.Host})
	if err = atomicJSONBytes(filepath.Join(s.dir, "download-credential.json"), raw); err != nil {
		return err
	}
	s.config.CredentialConfigured = true
	return nil
}
