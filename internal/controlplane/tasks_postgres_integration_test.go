package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/store"
)

func taskIntegrationServer(t *testing.T) (*Server, Session) {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	if _, err := store.ApplyPostgresMigrations(context.Background(), dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	actor := Session{User: User{ID: "task-owner-" + shortToken(16)}, Role: "admin", Permissions: rolePermissions("admin")}
	t.Cleanup(func() { db.Exec(`DELETE FROM control_plane_tasks WHERE created_by=$1`, actor.User.ID); db.Close() })
	s := &Server{managedIdentityFailures: &managedIdentityFailureCache{}, operations: &operationsState{db: db}, tasks: &taskRuntime{dir: filepath.Join(t.TempDir(), "input"), wake: make(chan struct{}, 2)}, fingerprints: fingerprint.NewManager(t.TempDir())}
	// Tests claim explicitly so restart and cancellation points are deterministic.
	s.tasks.once.Do(func() {})
	return s, actor
}

func TestOperationTaskPostgresPersistenceRecoveryAndBusinessResult(t *testing.T) {
	s, actor := taskIntegrationServer(t)
	path := filepath.Join(t.TempDir(), "fixture.tar.gz")
	version := "task-validation-" + shortToken(8)
	if _, err := fingerprint.BuildEmbeddedBundle(path, version, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	submit := func(key string) operationTask {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		part, e := writer.CreateFormFile("bundle", "fixture.tar.gz")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = part.Write(raw); e != nil {
			t.Fatal(e)
		}
		if e = writer.Close(); e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest("POST", "/api/v1/device-fingerprint-library/validate", &body)
		r.Header.Set("Content-Type", writer.FormDataContentType())
		r.Header.Set("Idempotency-Key", key)
		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, actor))
		w := httptest.NewRecorder()
		s.submitOperationTask(w, r, "/device-fingerprint-library/validate")
		if w.Code != 202 {
			t.Fatalf("submit: %d %s", w.Code, w.Body.String())
		}
		var job operationTask
		if e = json.Unmarshal(w.Body.Bytes(), &job); e != nil {
			t.Fatal(e)
		}
		return job
	}
	job := submit("package-1")
	if repeated := submit("package-1"); repeated.TaskID != job.TaskID {
		t.Fatal("multipart boundary created duplicate task")
	}
	// A process died with an expired lease after persistence, before completion.
	if _, err = s.operations.db.Exec(`UPDATE control_plane_tasks SET status='running',worker_id='terminated-worker',lease_until=now()-interval '1 minute',attempts=1 WHERE task_id=$1`, job.TaskID); err != nil {
		t.Fatal(err)
	}
	if !s.runNextOperationTask("recovered-worker") {
		t.Fatal("expired running task not recovered")
	}
	actual, err := s.readOperationTask(context.Background(), job.TaskID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Status != "completed" || actual.ResponseStatus != 200 {
		t.Fatalf("business result: %+v", actual)
	}
	var manifest fingerprint.BundleManifest
	if err = json.Unmarshal(actual.Result, &manifest); err != nil || manifest.Version != version {
		t.Fatalf("invalid business result: %s %v", actual.Result, err)
	}
	outsider := Session{User: User{ID: "another-owner"}, Role: "operator"}
	if _, err = s.readOperationTask(context.Background(), job.TaskID, outsider); !errors.Is(err, errTaskForbidden) {
		t.Fatal("task result crossed actor boundary")
	}
	if err = s.cancelOperationTask(context.Background(), job.TaskID); !errors.Is(err, errTaskTerminal) {
		t.Fatal("completed task reported as cancelled")
	}
	queued := submit("package-2")
	if err = s.cancelOperationTask(context.Background(), queued.TaskID); err != nil {
		t.Fatal(err)
	}
	if s.runNextOperationTask("cancelled-worker") {
		t.Fatal("cancelled task was executed")
	}
	actual, err = s.readOperationTask(context.Background(), queued.TaskID, actor)
	if err != nil || actual.Status != "cancelled" {
		t.Fatalf("cancellation: %+v %v", actual, err)
	}
}

func TestOperationTaskCancellationDoesNotMisreportAtomicActivation(t *testing.T) {
	s, actor := taskIntegrationServer(t)
	id := "task-atomic-" + shortToken(16)
	actorJSON, _ := json.Marshal(actor)
	_, err := s.operations.db.Exec(`INSERT INTO control_plane_tasks(task_id,kind,status,created_by,request_hash,actor,method,request_path,content_type,input_path,worker_id) VALUES($1,'/application-library/import','running',$2,'hash',$3,'POST','/api/v1/application-library/import','application/gzip','unused','atomic-worker')`, id, actor.User.ID, actorJSON)
	if err != nil {
		t.Fatal(err)
	}
	guard := &operationTaskCommit{id: id, worker: "atomic-worker"}
	defer func() {
		if guard.tx != nil {
			guard.tx.Rollback()
		}
		if guard.cancel != nil {
			guard.cancel()
		}
	}()
	ctx := context.WithValue(context.Background(), operationTaskCommitKey{}, guard)
	if err = s.operationCommitGuard(ctx)(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = s.cancelOperationTask(context.Background(), id)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("atomic cancellation should reject promptly: %v", err)
	}
	guard.tx.Rollback()
	guard.tx = nil
	if err = s.cancelOperationTask(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err = s.operationCommitGuard(ctx)(); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled task entered activation phase")
	}
}
