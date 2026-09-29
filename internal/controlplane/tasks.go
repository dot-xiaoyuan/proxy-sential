package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"proxy-sentinel/internal/appdomain"
	"proxy-sentinel/internal/fingerprint"
)

type taskRuntime struct {
	once sync.Once
	dir  string
	wake chan struct{}
}

var errTaskForbidden = errors.New("task belongs to another user")

type operationTask struct {
	TaskID         string          `json:"task_id"`
	Kind           string          `json:"kind"`
	Status         string          `json:"status"`
	CreatedAt      time.Time       `json:"created_at"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	Error          string          `json:"error,omitempty"`
	ResponseStatus int             `json:"response_status,omitempty"`
}

func asynchronousOperation(method, path string) bool {
	if method == "GET" {
		return strings.HasPrefix(path, "/actions/connectors/") && strings.HasSuffix(path, "/account-preview")
	}
	if method == "POST" && sharedDisconnectPath(path) {
		return true
	}
	if method != "POST" {
		return false
	}
	switch path {
	case "/application-library/pull", "/application-library/import", "/device-fingerprint-library/update", "/device-fingerprint-library/import", "/device-fingerprint-library/validate":
		return true
	}
	return strings.HasPrefix(path, "/actions/connectors/") && (strings.HasSuffix(path, "/test") || strings.HasSuffix(path, "/4k-database"))
}

// Uploads are streamed to durable private files; transmission is measured
// separately. Verification, parsing and external calls execute in two workers.
func (s *Server) submitOperationTask(w http.ResponseWriter, r *http.Request, path string) {
	if sharedDisconnectPath(path) {
		if strings.HasSuffix(path, "/disconnect") {
			actor := sessionFromContext(r.Context())
			for _, permission := range []string{"integrations:write", "actions:execute", "cases:write"} {
				if !sessionHasPermission(actor, permission) {
					writeError(w, 403, "permission_denied", "人工测试授权权限不足")
					return
				}
			}
			if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
				writeError(w, 400, "idempotency_key_required", "下线确认需要幂等键")
				return
			}
		}
		parts := strings.Split(path, "/")
		var exists bool
		if err := s.operations.db.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM shared_access_reviews WHERE review_id=$1)`, parts[3]).Scan(&exists); err != nil {
			writeError(w, 503, "review_unavailable", "复核记录读取失败")
			return
		}
		if !exists {
			writeError(w, 404, "review_not_found", "复核记录不存在")
			return
		}
	}
	if s.readOnly {
		writeError(w, 403, "read_only", "mutating operations are disabled")
		return
	}
	if path == "/device-fingerprint-library/update" && s.fingerprintOffline {
		writeError(w, 409, "offline_update_required", "control plane is offline; import a verified bundle")
		return
	}
	if strings.HasSuffix(path, "/account-preview") && r.URL.Query().Get("account_id") == "" {
		writeError(w, 400, "account_required", "account_id is required")
		return
	}
	if strings.HasPrefix(path, "/actions/connectors/") {
		parts := strings.Split(strings.TrimPrefix(path, "/actions/connectors/"), "/")
		if len(parts) != 2 || parts[0] == "" {
			writeError(w, 400, "bad_connector_task", "valid connector ID is required")
			return
		}
		ctx, cancel := contextWithRequestTimeout(r.Context())
		defer cancel()
		var exists bool
		if err := s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM enforcement_connectors WHERE connector_id=$1)`, parts[0]).Scan(&exists); err != nil {
			writeError(w, 503, "connector_storage_failed", err.Error())
			return
		}
		if !exists {
			writeError(w, 404, "connector_not_found", "connector not found")
			return
		}
		if strings.HasSuffix(path, "/account-preview") {
			if _, ok := s.nativeActions[parts[0]]; !ok {
				writeError(w, 409, "native_preview_unavailable", "native source is not configured")
				return
			}
		}
	}
	if err := os.MkdirAll(s.tasks.dir, 0700); err != nil {
		writeError(w, 503, "task_storage_failed", "task input directory unavailable")
		return
	}
	id := "task-" + shortToken(16)
	input := filepath.Join(s.tasks.dir, id+".input")
	f, err := os.OpenFile(input, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		writeError(w, 503, "task_storage_failed", "task input unavailable")
		return
	}
	accepted := false
	defer func() {
		f.Close()
		if !accepted {
			_ = os.Remove(input)
		}
	}()
	var source io.Reader = r.Body
	limit := int64(64 << 10)
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(path, "/device-fingerprint-library/") && (strings.HasSuffix(path, "/import") || strings.HasSuffix(path, "/validate")) {
		limit = int64(fingerprint.MaxBundleBytes)
		reader, e := r.MultipartReader()
		if e != nil {
			writeError(w, 400, "bad_fingerprint_bundle", "multipart field bundle is required")
			return
		}
		var part *multipart.Part
		for {
			part, e = reader.NextPart()
			if e != nil {
				break
			}
			if part.FormName() == "bundle" {
				break
			}
			part.Close()
		}
		if e != nil || part == nil {
			writeError(w, 400, "bad_fingerprint_bundle", "multipart field bundle is required")
			return
		}
		defer part.Close()
		source = part
		contentType = "application/gzip"
	} else if path == "/application-library/import" {
		limit = int64(appdomain.MaxBundleBytes)
	}
	if source == nil {
		source = strings.NewReader("")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(r.Method + "\n" + r.URL.RequestURI() + "\n"))
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(source, limit+1))
	if err != nil || n > limit {
		writeError(w, 400, "task_input_invalid", "input exceeds limit or upload failed")
		return
	}
	if path == "/application-library/pull" {
		raw, e := os.ReadFile(input)
		var params struct {
			Token string `json:"token"`
		}
		if e != nil || json.Unmarshal(raw, &params) != nil {
			writeError(w, 400, "application_update_failed", "invalid pull parameters")
			return
		}
	}
	if strings.HasSuffix(path, "/import") || strings.HasSuffix(path, "/validate") {
		reader, e := os.Open(input)
		var header [2]byte
		if e == nil {
			_, e = io.ReadFull(reader, header[:])
			reader.Close()
		}
		if e != nil || header != [2]byte{0x1f, 0x8b} {
			writeError(w, 400, "task_input_invalid", "gzip bundle is required")
			return
		}
	}
	if err = f.Sync(); err != nil {
		writeError(w, 503, "task_storage_failed", "task input persistence failed")
		return
	}
	if err = f.Close(); err != nil {
		writeError(w, 503, "task_storage_failed", "task input persistence failed")
		return
	}
	directory, err := os.Open(s.tasks.dir)
	if err == nil {
		err = directory.Sync()
		directory.Close()
	}
	if err != nil {
		writeError(w, 503, "task_storage_failed", "task input persistence failed")
		return
	}
	actor := sessionFromContext(r.Context())
	actor.CSRFToken = ""
	actorJSON, _ := json.Marshal(actor)
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		writeError(w, 503, "task_storage_failed", err.Error())
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-task-submissions'))`); err != nil {
		writeError(w, 503, "task_storage_failed", err.Error())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	digest := hex.EncodeToString(hash.Sum(nil))
	if key != "" {
		var existing, existingHash string
		err = tx.QueryRowContext(ctx, `SELECT task_id,request_hash FROM control_plane_tasks WHERE created_by=$1 AND idempotency_key=$2`, actor.User.ID, key).Scan(&existing, &existingHash)
		if err == nil {
			if existingHash != digest {
				writeError(w, 409, "idempotency_conflict", "key reused with different parameters")
				return
			}
			job, e := s.readOperationTask(ctx, existing, actor)
			if e != nil {
				writeError(w, 503, "task_storage_failed", e.Error())
				return
			}
			writeJSON(w, 202, job)
			return
		}
		if err != sql.ErrNoRows {
			writeError(w, 503, "task_storage_failed", err.Error())
			return
		}
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM control_plane_tasks WHERE status IN ('queued','running')`).Scan(&pending); err != nil {
		writeError(w, 503, "task_storage_failed", err.Error())
		return
	}
	if pending >= 1000 {
		writeError(w, 429, "task_queue_full", "task queue is full")
		return
	}
	var created time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO control_plane_tasks(task_id,kind,status,created_by,idempotency_key,request_hash,actor,method,request_path,content_type,input_path) VALUES($1,$2,'queued',$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10) RETURNING created_at`, id, path, actor.User.ID, key, digest, actorJSON, r.Method, r.URL.RequestURI(), contentType, input).Scan(&created)
	if err == nil && sharedDisconnectPath(path) {
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'shared_access.task.submit',$3,'persisted',now())`, "audit-"+id, actor.User.ID, id)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeError(w, 503, "task_storage_failed", err.Error())
		return
	}
	accepted = true
	s.startOperationWorkers()
	select {
	case s.tasks.wake <- struct{}{}:
	default:
	}
	s.appendAudit(r.Context(), "task.submit", id, "accepted")
	writeJSON(w, 202, operationTask{TaskID: id, Kind: path, Status: "queued", CreatedAt: created})
}

func (s *Server) readOperationTask(ctx context.Context, id string, actor Session) (operationTask, error) {
	var job operationTask
	var result []byte
	var owner string
	err := s.operations.db.QueryRowContext(ctx, `SELECT task_id,kind,status,created_by,created_at,completed_at,result,coalesce(error,''),coalesce(response_status,0) FROM control_plane_tasks WHERE task_id=$1`, id).Scan(&job.TaskID, &job.Kind, &job.Status, &owner, &job.CreatedAt, &job.CompletedAt, &result, &job.Error, &job.ResponseStatus)
	job.Result = json.RawMessage(result)
	if err != nil {
		return job, err
	}
	if owner != actor.User.ID && actor.Role != "admin" {
		return operationTask{}, errTaskForbidden
	}
	return job, nil
}

func (s *Server) handleOperationTasks(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations.db == nil {
		writeError(w, 404, "task_not_found", "task not found")
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/tasks/"), "/")
	actor := sessionFromContext(r.Context())
	job, err := s.readOperationTask(r.Context(), parts[0], actor)
	if err == sql.ErrNoRows {
		writeError(w, 404, "task_not_found", "task not found")
		return
	}
	if errors.Is(err, errTaskForbidden) {
		writeError(w, 403, "task_forbidden", "task belongs to another user")
		return
	}
	if err != nil {
		writeError(w, 503, "task_storage_failed", "task storage unavailable")
		return
	}
	if r.Method == "GET" && len(parts) == 1 {
		writeJSON(w, 200, job)
		return
	}
	if r.Method == "POST" && len(parts) == 2 && parts[1] == "cancel" {
		if job.Status == "completed" || job.Status == "failed" {
			writeError(w, 409, "task_terminal", "completed task cannot be cancelled")
			return
		}
		err = s.cancelOperationTask(r.Context(), job.TaskID)
		if errors.Is(err, errTaskTerminal) {
			writeError(w, 409, "task_terminal", "task already completed or activation is committing")
			return
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			writeError(w, 409, "task_committing", "rule activation is committing and cannot be cancelled")
			return
		}
		if err != nil {
			writeError(w, 503, "task_storage_failed", "task cancellation persistence failed")
			return
		}

		s.appendAudit(r.Context(), "task.cancel", job.TaskID, "cancelled")
		job, err = s.readOperationTask(r.Context(), job.TaskID, actor)
		if err != nil {
			writeError(w, 503, "task_storage_failed", err.Error())
			return
		}
		writeJSON(w, 200, job)
		return
	}
	writeError(w, 405, "task_operation_invalid", "invalid task operation")
}

func (s *Server) startOperationWorkers() {
	if s.tasks == nil || s.operations.db == nil {
		return
	}
	s.tasks.once.Do(func() {
		for i := 0; i < 2; i++ {
			go func() {
				worker := "worker-" + shortToken(16)
				for {
					worked := s.runNextOperationTask(worker)
					if worked {
						continue
					}
					select {
					case <-s.tasks.wake:
					case <-time.After(time.Second):
					}
				}
			}()
		}
	})
}

func (s *Server) runNextOperationTask(worker string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	_, _ = s.operations.db.ExecContext(ctx, `UPDATE control_plane_tasks SET status='failed',error='restart recovery retry budget exhausted',completed_at=now() WHERE status='running' AND lease_until<now() AND attempts>=3`)
	var id, method, requestPath, contentType, input string
	var actorJSON []byte
	err := s.operations.db.QueryRowContext(ctx, `UPDATE control_plane_tasks SET status='running',attempts=attempts+1,worker_id=$1,lease_until=now()+interval '30 seconds',started_at=coalesce(started_at,now()) WHERE task_id=(SELECT task_id FROM control_plane_tasks WHERE status='queued' OR (status='running' AND lease_until<now() AND attempts<3) ORDER BY created_at,task_id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING task_id,method,request_path,content_type,input_path,actor`, worker).Scan(&id, &method, &requestPath, &contentType, &input, &actorJSON)
	if err != nil {
		return false
	}
	guard := &operationTaskCommit{id: id, worker: worker}
	defer func() {
		if guard.tx != nil {
			guard.tx.Rollback()
		}
		if guard.cancel != nil {
			guard.cancel()
		}
	}()

	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if guard.atomicPhase.Load() {
					continue
				}
				renewCtx, renewCancel := context.WithTimeout(context.Background(), 2*time.Second)
				result, e := s.operations.db.ExecContext(renewCtx, `UPDATE control_plane_tasks SET lease_until=now()+interval '30 seconds' WHERE task_id=$1 AND worker_id=$2 AND status='running'`, id, worker)
				renewCancel()
				if e != nil {
					cancel()
					return
				}
				n, e := result.RowsAffected()
				if e != nil || n == 0 {
					cancel()
					return
				}
			}
		}
	}()
	buffer := &statisticsWriter{header: http.Header{}}
	func() {
		defer func() {
			if recover() != nil {
				buffer = &statisticsWriter{header: http.Header{}}
				writeError(buffer, 500, "task_execution_failed", "task execution failed")
			}
		}()
		var actor Session
		if err = json.Unmarshal(actorJSON, &actor); err != nil {
			writeError(buffer, 500, "task_actor_invalid", "task actor invalid")
			return
		}
		parsed, e := url.ParseRequestURI(requestPath)
		if e != nil || !asynchronousOperation(method, strings.TrimPrefix(parsed.Path, "/api/v1")) {
			writeError(buffer, 400, "task_operation_invalid", "task operation invalid")
			return
		}
		path := strings.TrimPrefix(parsed.Path, "/api/v1")
		if s.auth != nil && s.auth.enabled {
			var role string
			var disabled bool
			if e = s.operations.db.QueryRowContext(ctx, `SELECT role,disabled FROM local_users WHERE user_id=$1`, actor.User.ID).Scan(&role, &disabled); e != nil || disabled {
				writeError(buffer, 403, "task_actor_disabled", "task actor unavailable")
				return
			}
			actor.Role, actor.Permissions = role, rolePermissions(role)
			if permission := requiredPermission(method, path); permission != "" && !sessionHasPermission(actor, permission) {
				writeError(buffer, 403, "permission_denied", "task permission revoked")
				return
			}
		}
		if filepath.Dir(input) != s.tasks.dir {
			writeError(buffer, 400, "task_input_invalid", "task input unavailable")
			return
		}
		file, e := os.Open(input)
		if e != nil {
			writeError(buffer, 500, "task_input_unavailable", "task input unavailable")
			return
		}
		defer file.Close()
		var body io.ReadCloser = file
		if strings.HasPrefix(path, "/device-fingerprint-library/") && (strings.HasSuffix(path, "/import") || strings.HasSuffix(path, "/validate")) {
			reader, writer := io.Pipe()
			multipartWriter := multipart.NewWriter(writer)
			contentType = multipartWriter.FormDataContentType()
			go func() {
				part, e := multipartWriter.CreateFormFile("bundle", "bundle.tar.gz")
				if e == nil {
					_, e = io.Copy(part, file)
				}
				if e == nil {
					e = multipartWriter.Close()
				}
				writer.CloseWithError(e)
			}()
			body = reader
			defer reader.Close()
		}
		request, e := http.NewRequestWithContext(context.WithValue(context.WithValue(context.WithValue(ctx, sessionContextKey{}, actor), operationTaskContextKey{}, true), operationTaskCommitKey{}, guard), method, "http://localhost"+requestPath, body)
		if e != nil {
			writeError(buffer, 500, "task_request_invalid", "task request invalid")
			return
		}
		request.Header.Set("Content-Type", contentType)
		s.dispatchAPI(buffer, request, path)
	}()
	if buffer.status == 0 {
		buffer.status = 200
	}
	status, message := "completed", ""
	if buffer.status >= 400 || ctx.Err() != nil {
		status = "failed"
		message = fmt.Sprintf("operation returned HTTP %d", buffer.status)
		if ctx.Err() != nil {
			message = "task interrupted or execution deadline exceeded"
		}
	}
	result := buffer.body.Bytes()
	if !json.Valid(result) {
		result = []byte(`null`)
	}
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer finishCancel()
	var executor interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	} = s.operations.db
	if guard.tx != nil {
		executor = guard.tx
	}

	saved, err := executor.ExecContext(finishCtx, `UPDATE control_plane_tasks SET status=$3,result=$4,error=NULLIF($5,''),response_status=$6,completed_at=now(),lease_until=NULL WHERE task_id=$1 AND worker_id=$2 AND status='running'`, id, worker, status, result, message, buffer.status)
	var updated int64
	if err == nil {
		updated, err = saved.RowsAffected()
	}

	if err == nil && guard.tx != nil {
		err = guard.tx.Commit()
	}
	if err == nil && updated == 1 {
		s.appendAudit(finishCtx, "task.complete", id, status)
		_ = os.Remove(input)
	}
	return true
}

type operationTaskContextKey struct{}

var errTaskTerminal = errors.New("task already terminal")

func (s *Server) cancelOperationTask(ctx context.Context, id string) error {
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM control_plane_tasks WHERE task_id=$1 FOR UPDATE NOWAIT`, id).Scan(&status); err != nil {
		return err
	}
	if status == "completed" || status == "failed" {
		return errTaskTerminal
	}
	if status == "cancelled" {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE control_plane_tasks SET status='cancelled',completed_at=now(),lease_until=NULL WHERE task_id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}
