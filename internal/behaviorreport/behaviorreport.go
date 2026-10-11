// Package behaviorreport delivers normalized security-behaviour events to an
// external platform. It mirrors the legacy northbound reporting shape: an
// optional token fetch, a batched JSON POST and a configurable field mapping.
// Nothing here decides policy; it only reports what other components observed.
package behaviorreport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	EventPoisonBehavior = "poison_behavior"
	EventProxyBehavior  = "proxy_behavior"
	EventAIRelayAudit   = "ai_relay_audit"

	AuthNone         = "none"
	AuthBearer       = "bearer"
	AuthOAuth2Client = "oauth2_client_credentials"

	DefaultBatchSize  = 100
	DefaultTimeoutSec = 10
	MaxAttempts       = 6
	bodyLimit         = 1 << 20
)

type Channel struct {
	ChannelID          string            `json:"channel_id"`
	Name               string            `json:"name"`
	EndpointURL        string            `json:"endpoint_url"`
	TokenEndpoint      string            `json:"token_endpoint,omitempty"`
	TokenMethod        string            `json:"token_method,omitempty"`
	TokenScope         string            `json:"token_scope,omitempty"`
	AuthType           string            `json:"auth_type"`
	SourceSystemIP     string            `json:"source_system_ip,omitempty"`
	SourceSystemName   string            `json:"source_system_name,omitempty"`
	BatchSize          int               `json:"batch_size"`
	FlushIntervalSecs  int               `json:"flush_interval_seconds"`
	TimeoutSeconds     int               `json:"timeout_seconds"`
	TLSSkipVerify      bool              `json:"tls_skip_verify"`
	FieldMapping       map[string]string `json:"field_mapping"`
	SuccessStatusCodes []int             `json:"success_status_codes"`
	Enabled            bool              `json:"enabled"`
	Revision           int               `json:"revision"`

	Secret          string `json:"-"`
	EncryptedSecret string `json:"-"`
	HasSecret       bool   `json:"has_secret"`
}

// Event is one reported observation. Detail carries the raw key/value pairs the
// channel's field mapping may reference.
type Event struct {
	ReportID    string            `json:"report_id"`
	EventType   string            `json:"event_type"`
	SubjectType string            `json:"subject_type"`
	SubjectID   string            `json:"subject_id"`
	AccountID   string            `json:"account_id,omitempty"`
	IP          string            `json:"ip,omitempty"`
	Target      string            `json:"target,omitempty"`
	TargetType  string            `json:"target_type,omitempty"`
	OccurredAt  time.Time         `json:"occurred_at"`
	Detail      map[string]string `json:"detail,omitempty"`
}

func NormalizeChannel(channel *Channel) {
	if channel == nil {
		return
	}
	channel.ChannelID = strings.TrimSpace(channel.ChannelID)
	channel.Name = strings.TrimSpace(channel.Name)
	channel.EndpointURL = strings.TrimSpace(channel.EndpointURL)
	channel.TokenEndpoint = strings.TrimSpace(channel.TokenEndpoint)
	channel.TokenScope = strings.TrimSpace(channel.TokenScope)
	channel.AuthType = strings.ToLower(strings.TrimSpace(channel.AuthType))
	channel.TokenMethod = strings.ToUpper(strings.TrimSpace(channel.TokenMethod))
	if channel.AuthType == "" {
		channel.AuthType = AuthNone
	}
	if channel.TokenMethod == "" {
		channel.TokenMethod = http.MethodGet
	}
	if channel.BatchSize <= 0 {
		channel.BatchSize = DefaultBatchSize
	}
	if channel.BatchSize > 500 {
		channel.BatchSize = 500
	}
	if channel.TimeoutSeconds <= 0 {
		channel.TimeoutSeconds = DefaultTimeoutSec
	}
	if channel.TimeoutSeconds > 120 {
		channel.TimeoutSeconds = 120
	}
	if channel.FlushIntervalSecs <= 0 {
		channel.FlushIntervalSecs = 1
	}
	if len(channel.SuccessStatusCodes) == 0 {
		channel.SuccessStatusCodes = []int{http.StatusOK}
	}
	if channel.FieldMapping == nil {
		channel.FieldMapping = map[string]string{}
	}
	if channel.Revision < 1 {
		channel.Revision = 1
	}
}

func ValidateChannel(channel *Channel) error {
	if channel == nil {
		return fmt.Errorf("上报通道不能为空")
	}
	NormalizeChannel(channel)
	if channel.ChannelID == "" || channel.Name == "" {
		return fmt.Errorf("通道标识与名称不能为空")
	}
	if len(channel.ChannelID) > 128 || len(channel.Name) > 128 {
		return fmt.Errorf("通道标识或名称过长")
	}
	endpoint, err := url.Parse(channel.EndpointURL)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return fmt.Errorf("上报地址格式不正确")
	}
	switch channel.AuthType {
	case AuthNone, AuthBearer:
	case AuthOAuth2Client:
		token, err := url.Parse(channel.TokenEndpoint)
		if err != nil || token.Host == "" || (token.Scheme != "https" && token.Scheme != "http") {
			return fmt.Errorf("OAuth2 通道必须配置 token 地址")
		}
		if channel.TokenMethod != http.MethodGet && channel.TokenMethod != http.MethodPost {
			return fmt.Errorf("token 请求方法必须是 GET 或 POST")
		}
	default:
		return fmt.Errorf("鉴权方式不受支持")
	}
	for _, code := range channel.SuccessStatusCodes {
		if code < 100 || code > 599 {
			return fmt.Errorf("成功状态码不合法")
		}
	}
	if len(channel.FieldMapping) > 64 {
		return fmt.Errorf("字段映射条目过多")
	}
	return nil
}

func (c Channel) Redacted() Channel {
	c.HasSecret = c.HasSecret || c.EncryptedSecret != "" || c.Secret != ""
	c.Secret = ""
	c.EncryptedSecret = ""
	return c
}

// Payload renders one batch using the channel's field mapping. Mapping values
// are source expressions: "=literal" is a constant, "detail.key" reads the
// event detail, and any other value reads a top-level event field.
func (c Channel) Payload(events []Event) (map[string]any, error) {
	if len(events) == 0 {
		return map[string]any{}, nil
	}
	items := make([]map[string]any, 0, len(events))
	for _, event := range events {
		item := map[string]any{
			"event_type":  eventTypeForReport(event.EventType),
			"source":      "dpi",
			"occurred_at": event.OccurredAt.UTC().Format("2006-01-02 15:04:05"),
			"source_ip":   event.IP,
		}
		for target, source := range c.FieldMapping {
			item[target] = resolveMapping(source, event)
		}
		if _, ok := item["source_system_ip"]; !ok && c.SourceSystemIP != "" {
			item["source_system_ip"] = c.SourceSystemIP
		}
		if _, ok := item["source_system_name"]; !ok && c.SourceSystemName != "" {
			item["source_system_name"] = c.SourceSystemName
		}
		items = append(items, item)
	}
	if len(items) == 1 {
		return items[0], nil
	}
	return map[string]any{"items": items}, nil
}

// eventTypeForReport keeps the legacy platform vocabulary: it expects a
// behaviour classification rather than the internal event name.
func eventTypeForReport(eventType string) string {
	switch eventType {
	case EventPoisonBehavior:
		return "malware"
	case EventProxyBehavior:
		return "proxy"
	case EventAIRelayAudit:
		return "ai_relay"
	default:
		return eventType
	}
}

func resolveMapping(source string, event Event) any {
	source = strings.TrimSpace(source)
	if strings.HasPrefix(source, "=") {
		return strings.TrimPrefix(source, "=")
	}
	if strings.HasPrefix(source, "detail.") {
		return event.Detail[strings.TrimPrefix(source, "detail.")]
	}
	switch source {
	case "", "event_type":
		return eventTypeForReport(event.EventType)
	case "account", "account_id":
		return event.AccountID
	case "ip", "source_ip":
		return event.IP
	case "target":
		return event.Target
	case "target_type":
		return event.TargetType
	case "subject_id":
		return event.SubjectID
	case "report_id":
		return event.ReportID
	}
	return event.Detail[source]
}

type Result struct {
	StatusCode int
	RemoteID   string
	Body       string
}

type Sender struct {
	channel Channel
	secret  string
	client  *http.Client
}

func NewSender(channel Channel, secret string) (*Sender, error) {
	NormalizeChannel(&channel)
	if err := ValidateChannel(&channel); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: time.Duration(channel.TimeoutSeconds) * time.Second}
	if channel.TLSSkipVerify {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // explicit site opt-in
	}
	return &Sender{channel: channel, secret: secret, client: client}, nil
}

// Send posts one batch and reports whether the channel accepted it. A 4xx is a
// permanent rejection; everything else stays retryable.
func (s *Sender) Send(ctx context.Context, events []Event) (Result, error) {
	payload, err := s.channel.Payload(events)
	if err != nil {
		return Result{}, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Result{}, err
	}
	token, err := s.token(ctx)
	if err != nil {
		return Result{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.channel.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if len(events) == 1 && events[0].ReportID != "" {
		request.Header.Set("Idempotency-Key", events[0].ReportID)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return Result{}, err
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, bodyLimit))
	result := Result{StatusCode: response.StatusCode, Body: string(raw)}
	if s.accepted(response.StatusCode) {
		var decoded map[string]any
		if json.Unmarshal(raw, &decoded) == nil {
			if value, ok := decoded["id"].(string); ok {
				result.RemoteID = value
			}
		}
		return result, nil
	}
	message := fmt.Errorf("平台返回 HTTP %d: %s", response.StatusCode, truncate(result.Body, 256))
	if response.StatusCode >= 400 && response.StatusCode < 500 {
		return result, PermanentError{Err: message}
	}
	return result, message
}

func (s *Sender) accepted(status int) bool {
	for _, code := range s.channel.SuccessStatusCodes {
		if code == status {
			return true
		}
	}
	return false
}

// token performs the optional credential exchange. A GET token endpoint returns
// the token in the body; the legacy platform used that shape.
func (s *Sender) token(ctx context.Context) (string, error) {
	if s.channel.AuthType == AuthNone {
		return "", nil
	}
	if s.channel.AuthType == AuthBearer {
		if s.secret == "" {
			return "", fmt.Errorf("上报通道未配置密钥")
		}
		return s.secret, nil
	}
	if s.channel.TokenEndpoint == "" || s.secret == "" {
		return "", fmt.Errorf("上报通道未配置令牌地址或密钥")
	}
	var request *http.Request
	var err error
	if s.channel.TokenMethod == http.MethodPost {
		form := url.Values{}
		if s.channel.TokenScope != "" {
			form.Set("scope", s.channel.TokenScope)
		}
		request, err = http.NewRequestWithContext(ctx, http.MethodPost, s.channel.TokenEndpoint, strings.NewReader(form.Encode()))
		if err == nil {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		endpoint := s.channel.TokenEndpoint
		if s.channel.TokenScope != "" {
			endpoint += "?scope=" + url.QueryEscape(s.channel.TokenScope)
		}
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	}
	if err != nil {
		return "", err
	}
	request.Header.Set("X-Proxy-Sentinel-Credential", s.secret)
	response, err := s.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("获取上报令牌失败: %w", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, bodyLimit))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("获取上报令牌失败: HTTP %d", response.StatusCode)
	}
	token := extractToken(raw)
	if token == "" {
		return "", fmt.Errorf("上报令牌响应缺少令牌字段")
	}
	return token, nil
}

func extractToken(raw []byte) string {
	var decoded map[string]any
	if json.Unmarshal(raw, &decoded) != nil {
		return ""
	}
	for _, key := range []string{"access_token", "accessToken", "token", "data"} {
		switch value := decoded[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return value
			}
		case map[string]any:
			for _, nested := range []string{"access_token", "accessToken", "token"} {
				if text, ok := value[nested].(string); ok && strings.TrimSpace(text) != "" {
					return text
				}
			}
		}
	}
	return ""
}

// PermanentError marks a rejection that must not be retried.
type PermanentError struct{ Err error }

func (e PermanentError) Error() string { return e.Err.Error() }
func (e PermanentError) Unwrap() error { return e.Err }
func (e PermanentError) Permanent() bool {
	return true
}

func IsPermanent(err error) bool {
	for err != nil {
		if candidate, ok := err.(interface{ Permanent() bool }); ok {
			return candidate.Permanent()
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

// Backoff is the retry delay for an attempt; the exponent is clamped before the
// shift so a large attempt cannot overflow.
func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	const maxShift = 12
	shift := attempt - 1
	if shift > maxShift {
		shift = maxShift
	}
	delay := time.Duration(1<<uint(shift)) * time.Second
	if delay > time.Hour {
		delay = time.Hour
	}
	return delay
}

// IdempotencyKey is stable for an event type, subject and window so a replayed
// scan never reports the same observation twice.
func IdempotencyKey(eventType, subject, target, window string) string {
	parts := []string{eventType, subject, target, window}
	sort.Strings(parts[1:])
	return strings.Join(parts, "|")
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
