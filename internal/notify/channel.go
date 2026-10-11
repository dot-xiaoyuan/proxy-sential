package notify

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	ChannelTypeHTTP    = "http"
	ChannelTypeSRunSMS = "srun_sms"

	AuthNone            = "none"
	AuthBearer          = "bearer"
	AuthBasic           = "basic"
	AuthOAuth2Client    = "oauth2_client_credentials"
	DefaultTimeoutSec   = 10
	MaxTimeoutSec       = 120
	DefaultBodyLimit    = 1 << 20
	MaxNotificationTry  = 8
	DefaultSRunSMSAppID = ""
)

type ChannelConfig struct {
	// Headers are static request headers. Values are configuration, not user
	// input, but they are still not logged.
	Headers map[string]string `json:"headers,omitempty"`
	// ClientID accompanies the sealed secret for basic and OAuth2 channels.
	ClientID string `json:"client_id,omitempty"`
	// MessageTypeCode/SendTypes/SenderField drive the SRun/Supwisdom preset.
	MessageTypeCode string   `json:"message_type_code,omitempty"`
	SendTypes       []string `json:"send_types,omitempty"`
	// TLSSkipVerify stays false unless a site explicitly opts out.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`
	TimeoutSec    int  `json:"timeout_seconds,omitempty"`
}

func (c ChannelConfig) timeout() int {
	if c.TimeoutSec <= 0 {
		return DefaultTimeoutSec
	}
	if c.TimeoutSec > MaxTimeoutSec {
		return MaxTimeoutSec
	}
	return c.TimeoutSec
}

// Channel is the delivery configuration. Secret holds the sealed value when
// read from storage and is never serialised to clients.
type Channel struct {
	ChannelID     string        `json:"channel_id"`
	Name          string        `json:"name"`
	ChannelType   string        `json:"channel_type"`
	EndpointURL   string        `json:"endpoint_url"`
	TokenEndpoint string        `json:"token_endpoint,omitempty"`
	TokenScope    string        `json:"token_scope,omitempty"`
	AuthType      string        `json:"auth_type"`
	Config        ChannelConfig `json:"config"`
	IsDefault     bool          `json:"is_default"`
	Enabled       bool          `json:"enabled"`
	Revision      int           `json:"revision"`

	Secret          string `json:"-"`
	EncryptedSecret string `json:"-"`
	HasSecret       bool   `json:"has_secret"`
}

func ValidateChannel(c *Channel) error {
	if c == nil {
		return fmt.Errorf("通道不能为空")
	}
	c.ChannelID = strings.TrimSpace(c.ChannelID)
	c.Name = strings.TrimSpace(c.Name)
	c.ChannelType = strings.TrimSpace(c.ChannelType)
	c.AuthType = strings.TrimSpace(c.AuthType)
	c.EndpointURL = strings.TrimSpace(c.EndpointURL)
	c.TokenEndpoint = strings.TrimSpace(c.TokenEndpoint)
	c.TokenScope = strings.TrimSpace(c.TokenScope)
	if c.ChannelID == "" || c.Name == "" {
		return fmt.Errorf("通道标识与名称不能为空")
	}
	if len(c.ChannelID) > 128 || len(c.Name) > 128 {
		return fmt.Errorf("通道标识或名称过长")
	}
	if c.ChannelType == "" {
		c.ChannelType = ChannelTypeHTTP
	}
	if c.ChannelType != ChannelTypeHTTP && c.ChannelType != ChannelTypeSRunSMS {
		return fmt.Errorf("通道类型必须是 http 或 srun_sms")
	}
	if c.AuthType == "" {
		c.AuthType = AuthNone
	}
	switch c.AuthType {
	case AuthNone, AuthBearer, AuthBasic, AuthOAuth2Client:
	default:
		return fmt.Errorf("鉴权方式不受支持")
	}
	endpoint, err := url.Parse(c.EndpointURL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return fmt.Errorf("通道地址格式不正确")
	}
	if endpoint.Scheme != "https" && endpoint.Scheme != "http" {
		return fmt.Errorf("通道地址必须使用 http 或 https")
	}
	if c.AuthType == AuthOAuth2Client {
		token, err := url.Parse(c.TokenEndpoint)
		if err != nil || token.Scheme == "" || token.Host == "" {
			return fmt.Errorf("OAuth2 通道必须配置 token 地址")
		}
		if token.Scheme != "https" && token.Scheme != "http" {
			return fmt.Errorf("token 地址必须使用 http 或 https")
		}
	}
	if c.Config.TimeoutSec < 0 || c.Config.TimeoutSec > MaxTimeoutSec {
		return fmt.Errorf("超时时间必须在 0 到 %d 秒之间", MaxTimeoutSec)
	}
	if c.ChannelType == ChannelTypeSRunSMS && strings.TrimSpace(c.Config.MessageTypeCode) == "" {
		return fmt.Errorf("短信通道必须配置消息类型编码")
	}
	if c.Revision < 1 {
		c.Revision = 1
	}
	c.HasSecret = c.EncryptedSecret != "" || c.Secret != ""
	return nil
}

// Redacted returns a copy safe to serialise back to a client.
func (c Channel) Redacted() Channel {
	c.HasSecret = c.HasSecret || c.EncryptedSecret != "" || c.Secret != ""
	c.Secret = ""
	c.EncryptedSecret = ""
	return c
}
