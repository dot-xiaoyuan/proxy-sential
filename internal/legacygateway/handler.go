package legacygateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/actionreceipt"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Secret, TargetURL, TargetToken, StatePath string
	Client                                    *http.Client
	Now                                       func() time.Time
}
type Handler struct {
	options   Options
	mu        sync.Mutex
	completed map[string]string
}
type completionState struct {
	Version   int               `json:"version"`
	Completed map[string]string `json:"completed"`
}
type actionRequest struct {
	ActionID string `json:"action_id"`
	Action   string `json:"action"`
	Revoke   bool   `json:"revoke"`
	Duration int    `json:"duration_seconds"`
	Subject  struct {
		AccountID  string `json:"account_id"`
		EndpointID string `json:"endpoint_id"`
		IP         string `json:"ip"`
		SessionID  string `json:"session_id"`
	} `json:"subject"`
}

func New(options Options) (*Handler, error) {
	if options.Secret == "" || options.TargetURL == "" {
		return nil, fmt.Errorf("connector secret and target URL are required")
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: 7 * time.Second}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	h := &Handler{options: options, completed: map[string]string{}}
	if options.StatePath != "" {
		data, err := os.ReadFile(options.StatePath)
		if err == nil {
			var state completionState
			if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 || state.Completed == nil {
				return nil, fmt.Errorf("invalid or legacy completion state requires review; refusing to resend potentially completed actions")
			}
			h.completed = state.Completed
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	timestamp := r.Header.Get("X-Proxy-Sentinel-Timestamp")
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil || h.options.Now().UTC().Sub(parsed.UTC()) > 5*time.Minute || parsed.UTC().Sub(h.options.Now().UTC()) > time.Minute {
		http.Error(w, "stale signature", http.StatusUnauthorized)
		return
	}
	if !hmac.Equal([]byte(signature(h.options.Secret, timestamp, body)), []byte(r.Header.Get("X-Proxy-Sentinel-Signature"))) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	idempotency := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotency == "" {
		http.Error(w, "missing idempotency key", 400)
		return
	}
	h.mu.Lock()
	existing, ok := h.completed[idempotency]
	h.mu.Unlock()
	if ok {
		writeJSON(w, 200, map[string]string{"action_id": existing, "status": "completed"})
		return
	}
	var input actionRequest
	if err := json.Unmarshal(body, &input); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	legacyAction := input.Action
	if input.Revoke {
		legacyAction = "release"
	}
	payload, _ := json.Marshal(map[string]any{"request_id": idempotency, "action": legacyAction, "username": input.Subject.AccountID, "ip": input.Subject.IP, "session_id": input.Subject.SessionID, "device_id": input.Subject.EndpointID, "duration": input.Duration})
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, h.options.TargetURL, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotency)
	if h.options.TargetToken != "" {
		request.Header.Set("Authorization", "Bearer "+h.options.TargetToken)
	}
	response, err := h.options.Client.Do(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if readErr != nil {
		http.Error(w, "incomplete upstream action receipt", http.StatusBadGateway)
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		http.Error(w, fmt.Sprintf("legacy gateway returned %s", response.Status), http.StatusBadGateway)
		return
	}

	remoteID, receiptErr := actionreceipt.Completed(responseBody, input.Revoke)
	if receiptErr != nil {
		http.Error(w, receiptErr.Error(), http.StatusBadGateway)
		return
	}

	h.mu.Lock()
	h.completed[idempotency] = remoteID
	err = h.saveLocked()
	h.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]string{"action_id": remoteID, "status": "completed"})
}

func (h *Handler) saveLocked() error {
	if h.options.StatePath == "" {
		return nil
	}
	data, _ := json.Marshal(completionState{Version: 1, Completed: h.completed})
	if err := os.MkdirAll(filepath.Dir(h.options.StatePath), 0o750); err != nil {
		return err
	}
	temp := h.options.StatePath + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, h.options.StatePath)
}
func signature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:20]
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
