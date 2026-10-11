package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTemplateRenderUsesWhitelistedVariablesOnly(t *testing.T) {
	template := Template{TemplateID: "t1", Name: "提醒", Subject: "策略提醒", Body: "账号 {{account}} 在 {{ip}} 触发 {{policy_name}}"}
	if err := ValidateTemplate(&template); err != nil {
		t.Fatalf("validate: %v", err)
	}
	subject, body, missing := template.Render(map[string]string{"account": "u1", "ip": "10.0.0.1", "policy_name": "防代理"})
	if subject != "策略提醒" || body != "账号 u1 在 10.0.0.1 触发 防代理" {
		t.Fatalf("unexpected render: %q / %q", subject, body)
	}
	if len(missing) != 0 {
		t.Fatalf("unexpected missing: %v", missing)
	}
}

func TestTemplateRenderReportsMissingVariablesAsEmpty(t *testing.T) {
	template := Template{TemplateID: "t1", Name: "提醒", Body: "账号 {{account}} 联系方式 {{contact_number}}"}
	if err := ValidateTemplate(&template); err != nil {
		t.Fatalf("validate: %v", err)
	}
	_, body, missing := template.Render(map[string]string{"account": "u1"})
	if body != "账号 u1 联系方式 " {
		t.Fatalf("missing variables must render empty, got %q", body)
	}
	if len(missing) != 1 || missing[0] != "contact_number" {
		t.Fatalf("expected contact_number reported missing, got %v", missing)
	}
}

func TestTemplateRejectsUnknownVariable(t *testing.T) {
	template := Template{TemplateID: "t1", Name: "提醒", Body: "{{secret_env}}"}
	err := ValidateTemplate(&template)
	if err == nil || !strings.Contains(err.Error(), "secret_env") {
		t.Fatalf("expected unknown variable rejection, got %v", err)
	}
}

func TestTemplateDoesNotEvaluateExpressions(t *testing.T) {
	// Anything that is not a bare identifier placeholder must survive verbatim:
	// there is no expression evaluation to exploit.
	template := Template{TemplateID: "t1", Name: "提醒", Body: "{{account}} {{ 7*7 }} {{account|upper}} {{}}"}
	if err := ValidateTemplate(&template); err != nil {
		t.Fatalf("validate: %v", err)
	}
	_, body, _ := template.Render(map[string]string{"account": "u1"})
	if body != "u1 {{ 7*7 }} {{account|upper}} {{}}" {
		t.Fatalf("unexpected render: %q", body)
	}
}

func TestValidateTemplateRequiresBodyAndIdentifier(t *testing.T) {
	cases := []Template{
		{Name: "n", Body: "x"},
		{TemplateID: "t", Body: "x"},
		{TemplateID: "t", Name: "n", Body: "   "},
	}
	for _, item := range cases {
		candidate := item
		if err := ValidateTemplate(&candidate); err == nil {
			t.Fatalf("expected rejection for %+v", item)
		}
	}
}

func TestValidateChannel(t *testing.T) {
	valid := Channel{ChannelID: "c1", Name: "值班 Webhook", ChannelType: ChannelTypeHTTP, EndpointURL: "https://example.invalid/hook", AuthType: AuthBearer}
	if err := ValidateChannel(&valid); err != nil {
		t.Fatalf("validate: %v", err)
	}
	invalid := []Channel{
		{ChannelID: "c", Name: "n", EndpointURL: "ftp://x"},
		{ChannelID: "c", Name: "n", EndpointURL: "https://x", AuthType: "kerberos"},
		{ChannelID: "c", Name: "n", ChannelType: ChannelTypeSRunSMS, EndpointURL: "https://x"},
		{ChannelID: "c", Name: "n", EndpointURL: "https://x", AuthType: AuthOAuth2Client},
	}
	for _, item := range invalid {
		candidate := item
		if err := ValidateChannel(&candidate); err == nil {
			t.Fatalf("expected rejection for %+v", item)
		}
	}
}

func TestChannelRedactedHidesSecret(t *testing.T) {
	channel := Channel{ChannelID: "c1", Name: "n", ChannelType: ChannelTypeHTTP, EndpointURL: "https://example.invalid", AuthType: AuthBearer, Secret: "s3cret", EncryptedSecret: "sealed"}
	redacted := channel.Redacted()
	if redacted.Secret != "" || redacted.EncryptedSecret != "" {
		t.Fatalf("secret leaked: %+v", redacted)
	}
	if !redacted.HasSecret {
		t.Fatal("expected has_secret to remain true")
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	if Backoff(1) != time.Second || Backoff(2) != 2*time.Second {
		t.Fatalf("unexpected backoff: %v %v", Backoff(1), Backoff(2))
	}
	if Backoff(0) != time.Second {
		t.Fatalf("attempt 0 must clamp to 1: %v", Backoff(0))
	}
	if Backoff(50) != time.Hour {
		t.Fatalf("backoff must cap at one hour, got %v", Backoff(50))
	}
}

func TestHTTPSenderPostsRenderedBodyWithIdempotency(t *testing.T) {
	var received map[string]any
	var header http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &received)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"messageId":"remote-1"}`))
	}))
	defer server.Close()

	channel := Channel{ChannelID: "c1", Name: "n", ChannelType: ChannelTypeHTTP, EndpointURL: server.URL, AuthType: AuthBearer, Config: ChannelConfig{Headers: map[string]string{"X-Site": "ncu"}}}
	sender, err := NewSender(channel)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}
	result, err := sender.Send(context.Background(), Request{Channel: channel, Secret: "tok", Subject: "主题", Body: "正文", Variables: map[string]string{"account": "u1"}, IdempotencyKey: "key-1"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if result.RemoteID != "remote-1" || result.StatusCode != 200 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if header.Get("Authorization") != "Bearer tok" || header.Get("Idempotency-Key") != "key-1" || header.Get("X-Site") != "ncu" {
		t.Fatalf("unexpected headers: %+v", header)
	}
	if received["body"] != "正文" {
		t.Fatalf("unexpected payload: %+v", received)
	}
}

func TestHTTPSenderClassifiesClientErrorAsPermanent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad"))
	}))
	defer server.Close()
	channel := Channel{ChannelID: "c1", Name: "n", ChannelType: ChannelTypeHTTP, EndpointURL: server.URL, AuthType: AuthNone}
	sender, _ := NewSender(channel)
	_, err := sender.Send(context.Background(), Request{Channel: channel})
	if err == nil || !IsPermanent(err) {
		t.Fatalf("expected permanent error, got %v", err)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer failing.Close()
	transient := Channel{ChannelID: "c2", Name: "n", ChannelType: ChannelTypeHTTP, EndpointURL: failing.URL, AuthType: AuthNone}
	transientSender, _ := NewSender(transient)
	_, err = transientSender.Send(context.Background(), Request{Channel: transient})
	if err == nil || IsPermanent(err) {
		t.Fatalf("expected retryable error, got %v", err)
	}
}

func TestSRunSMSSenderFetchesTokenThenSends(t *testing.T) {
	var tokenCalls, sendCalls int
	var sendBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			tokenCalls++
			if r.Header.Get("Authorization") == "" {
				t.Error("token request must carry client credentials")
			}
			_, _ = w.Write([]byte(`{"access_token":"tok-1"}`))
		case "/send":
			sendCalls++
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &sendBody)
			if r.Header.Get("Authorization") != "Bearer tok-1" {
				t.Errorf("unexpected auth: %s", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"code":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	channel := Channel{ChannelID: "c1", Name: "短信", ChannelType: ChannelTypeSRunSMS, EndpointURL: server.URL + "/send", TokenEndpoint: server.URL + "/oauth2/token", TokenScope: "messagecenter:v1:sendMessage", AuthType: AuthOAuth2Client, Config: ChannelConfig{ClientID: "id", MessageTypeCode: "CODE1"}}
	sender, err := NewSender(channel)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}
	if _, err = sender.Send(context.Background(), Request{Channel: channel, Secret: "sec", Subject: "标题", Body: "正文", Variables: map[string]string{"account": "u1"}}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if tokenCalls != 1 || sendCalls != 1 {
		t.Fatalf("unexpected calls: token=%d send=%d", tokenCalls, sendCalls)
	}
	if sendBody["messageTypeCode"] != "CODE1" {
		t.Fatalf("unexpected body: %+v", sendBody)
	}
}
