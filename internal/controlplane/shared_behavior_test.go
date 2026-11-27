package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxy-sentinel/internal/store"
)

type stubSharedBehaviorReader struct {
	store.Reader
	listErr error
}

func (s stubSharedBehaviorReader) ListSharedBehavior(context.Context, store.SharedBehaviorQuery) (store.SharedBehaviorPage, error) {
	return store.SharedBehaviorPage{}, s.listErr
}

func (s stubSharedBehaviorReader) GetSharedBehavior(context.Context, string) (store.SharedBehaviorDetail, bool, error) {
	return store.SharedBehaviorDetail{}, false, nil
}

func TestHandleSharedBehaviorMapsTimeoutAndErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "查询超时返回504而非400",
			err:        context.DeadlineExceeded,
			wantStatus: http.StatusGatewayTimeout,
			wantCode:   "shared_behavior_timeout",
		},
		{
			name:       "非法参数返回400",
			err:        errors.New("invalid shared behavior view"),
			wantStatus: http.StatusBadRequest,
			wantCode:   "shared_behavior_query_invalid",
		},
		{
			name:       "其他存储异常返回503",
			err:        errors.New("connection refused"),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "shared_behavior_unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{reader: stubSharedBehaviorReader{listErr: tc.err}}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/shared-access/observations?view=current", nil)
			rec := httptest.NewRecorder()
			srv.handleSharedBehavior(rec, req, "/shared-access/observations")

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload["code"] != tc.wantCode {
				t.Fatalf("code = %v, want %s", payload["code"], tc.wantCode)
			}
		})
	}
}
