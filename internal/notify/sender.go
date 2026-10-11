package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Request struct {
	Channel        Channel
	Secret         string
	Subject        string
	Body           string
	Variables      map[string]string
	IdempotencyKey string
}

type Result struct {
	StatusCode int
	RemoteID   string
	Response   string
}

type Sender interface {
	Send(ctx context.Context, request Request) (Result, error)
}

// NewSender builds the provider for a channel. An unknown channel type is a
// configuration error, never a silent no-op.
func NewSender(channel Channel) (Sender, error) {
	client := &http.Client{Timeout: time.Duration(channel.Config.timeout()) * time.Second}
	if channel.Config.TLSSkipVerify {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // site-opt-in only
	}
	switch channel.ChannelType {
	case ChannelTypeHTTP, "":
		return &httpSender{client: client}, nil
	case ChannelTypeSRunSMS:
		return &srunSMSSender{client: client}, nil
	default:
		return nil, fmt.Errorf("unsupported notification channel type %q", channel.ChannelType)
	}
}

func applyAuth(request *http.Request, channel Channel, secret string) error {
	switch channel.AuthType {
	case AuthNone, "":
		return nil
	case AuthBearer:
		if secret == "" {
			return fmt.Errorf("通道未配置密钥")
		}
		request.Header.Set("Authorization", "Bearer "+secret)
		return nil
	case AuthBasic:
		if secret == "" {
			return fmt.Errorf("通道未配置密钥")
		}
		request.SetBasicAuth(channel.Config.ClientID, secret)
		return nil
	default:
		return fmt.Errorf("鉴权方式不受支持")
	}
}

type httpSender struct{ client *http.Client }

func (s *httpSender) Send(ctx context.Context, request Request) (Result, error) {
	payload := map[string]any{
		"subject":   request.Subject,
		"body":      request.Body,
		"variables": request.Variables,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Result{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, request.Channel.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if request.IdempotencyKey != "" {
		httpRequest.Header.Set("Idempotency-Key", request.IdempotencyKey)
	}
	for key, value := range request.Channel.Config.Headers {
		httpRequest.Header.Set(key, value)
	}
	if err := applyAuth(httpRequest, request.Channel, request.Secret); err != nil {
		return Result{}, err
	}
	return doRequest(s.client, httpRequest)
}

// srunSMSSender mirrors the legacy Supwisdom message-centre flow: an OAuth2
// client-credentials token followed by a messageSend POST whose body carries
// the rendered parameter block. It is an opt-in preset because the site
// endpoint and credentials are deployment facts.
type srunSMSSender struct{ client *http.Client }

func (s *srunSMSSender) Send(ctx context.Context, request Request) (Result, error) {
	token, err := s.token(ctx, request)
	if err != nil {
		return Result{}, err
	}
	parameters := map[string]string{}
	for key, value := range request.Variables {
		parameters[key] = value
	}
	parameters["content"] = request.Body
	sendTypes := request.Channel.Config.SendTypes
	if len(sendTypes) == 0 {
		sendTypes = []string{"SMS", "WECHAT"}
	}
	payload := map[string]any{
		"messageTypeCode": request.Channel.Config.MessageTypeCode,
		"sendType":        sendTypes,
		"toPersons":       request.Variables["account"],
		"data": map[string]any{
			"title":          request.Subject,
			"paramValueJson": parameters,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Result{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, request.Channel.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	if request.IdempotencyKey != "" {
		httpRequest.Header.Set("Idempotency-Key", request.IdempotencyKey)
	}
	for key, value := range request.Channel.Config.Headers {
		httpRequest.Header.Set(key, value)
	}
	return doRequest(s.client, httpRequest)
}

func (s *srunSMSSender) token(ctx context.Context, request Request) (string, error) {
	clientID, clientSecret := request.Channel.Config.ClientID, request.Secret
	if clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("短信通道未配置客户端凭据")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope := strings.TrimSpace(request.Channel.TokenScope); scope != "" {
		form.Set("scope", scope)
	}
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, request.Channel.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret)))
	response, err := s.client.Do(tokenRequest)
	if err != nil {
		return "", fmt.Errorf("获取消息通道令牌失败: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, DefaultBodyLimit))
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("获取消息通道令牌失败: HTTP %d", response.StatusCode)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", fmt.Errorf("消息通道令牌响应无法解析")
	}
	token := firstString(decoded, "access_token", "accessToken", "token")
	if token == "" {
		if nested, ok := decoded["data"].(map[string]any); ok {
			token = firstString(nested, "access_token", "accessToken", "token")
		}
	}
	if token == "" {
		return "", fmt.Errorf("消息通道令牌响应缺少 access_token")
	}
	return token, nil
}

func firstString(source map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := source[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func doRequest(client *http.Client, request *http.Request) (Result, error) {
	response, err := client.Do(request)
	if err != nil {
		return Result{}, err
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, DefaultBodyLimit))
	result := Result{StatusCode: response.StatusCode, Response: string(raw)}
	if readErr != nil {
		return result, readErr
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		var decoded map[string]any
		if json.Unmarshal(raw, &decoded) == nil {
			result.RemoteID = firstString(decoded, "messageId", "message_id", "id", "notification_id")
		}
		return result, nil
	}
	// 4xx is a permanent rejection: surface it so the caller stops retrying.
	if response.StatusCode >= 400 && response.StatusCode < 500 {
		return result, PermanentError{Err: fmt.Errorf("通道拒绝请求: HTTP %d: %s", response.StatusCode, truncate(result.Response, 256))}
	}
	return result, fmt.Errorf("通道暂时不可用: HTTP %d: %s", response.StatusCode, truncate(result.Response, 256))
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// PermanentError marks a rejection that must not be retried (for example a 4xx
// from the channel). Transient failures stay retryable.
type PermanentError struct{ Err error }

func (e PermanentError) Error() string { return e.Err.Error() }
func (e PermanentError) Unwrap() error { return e.Err }
func (e PermanentError) Permanent() bool {
	return true
}

func IsPermanent(err error) bool {
	var typed interface{ Permanent() bool }
	return errors.As(err, &typed) && typed.Permanent()
}

// Backoff is the retry delay for the given attempt (1-based). The exponent is
// clamped before shifting so a large attempt cannot overflow the duration, and
// the result is capped so a permanently broken channel cannot pin a worker slot.
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
