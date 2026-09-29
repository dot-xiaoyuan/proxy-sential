package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
)

func TestPostgres4KDatabasePasswordEncryptedAndPreserved(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := fmt.Sprintf("auth-database-%d", time.Now().UnixNano())
	defer db.ExecContext(context.Background(), `DELETE FROM enforcement_connectors WHERE connector_id=$1`, id)
	if _, err = db.ExecContext(ctx, `INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,action_mapping,encrypted_secret,mode,enabled,shadow_ready,updated_by) VALUES($1,'authorization test','https://example.test','{}',''::bytea,'shadow',false,false,'test')`, id); err != nil {
		t.Fatal(err)
	}
	s := &Server{operations: &operationsState{db: db}, actionMasterKey: []byte("isolated-test-master-key-1234")}
	path := "/api/v1/actions/connectors/" + id + "/4k-database"
	call := func(method, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleActions(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}
	cfg := srunapi.AuthorizationDatabase{Host: "192.0.2.190", Port: 3306, Database: "srun", Username: "readonly", Password: "private-database-test-password"}
	raw, _ := json.Marshal(cfg)
	w := call(http.MethodPut, string(raw))
	if w.Code != 200 || strings.Contains(w.Body.String(), cfg.Password) {
		t.Fatalf("save failed or leaked: status %d", w.Code)
	}
	var encrypted, public []byte
	if err = db.QueryRowContext(ctx, `SELECT encrypted_password,public_config FROM enforcement_4k_databases WHERE connector_id=$1`, id).Scan(&encrypted, &public); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), cfg.Password) || strings.Contains(string(encrypted), cfg.Password) {
		t.Fatal("password persisted in cleartext")
	}
	w = call(http.MethodGet, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "password\":") {
		t.Fatal("password returned by GET")
	}
	cfg.Password = ""
	cfg.AuthorizationID = 8
	raw, _ = json.Marshal(cfg)
	if w = call(http.MethodPut, string(raw)); w.Code != 200 {
		t.Fatalf("blank password update: %d", w.Code)
	}
	got, exists, err := s.load4KDatabase(ctx, id, true)
	if err != nil || !exists || got.Password != "private-database-test-password" || got.AuthorizationID != 8 {
		t.Fatal("password or selection lost after update")
	}
	var preserved []byte
	if err = db.QueryRowContext(ctx, `SELECT encrypted_password FROM enforcement_4k_databases WHERE connector_id=$1`, id).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	if string(preserved) != string(encrypted) {
		t.Fatal("blank password replaced encrypted password")
	}
	if w = call(http.MethodPut, `{"host":"db","port":3306,"database":"srun","username":"u","authorization_id":-1}`); w.Code != 400 {
		t.Fatal("invalid selection accepted")
	}
	if w = call(http.MethodPut, string(raw)+`{}`); w.Code != 400 {
		t.Fatal("trailing JSON accepted")
	}

	if mysqlDSN := os.Getenv("PROXY_SENTINEL_TEST_MYSQL_DSN"); mysqlDSN != "" {
		parsed, err := mysql.ParseDSN(mysqlDSN)
		if err != nil || parsed.DBName != "sentinel_auth_test" {
			t.Fatal("isolated MySQL DSN required")
		}
		fixture, err := sql.Open("mysql", mysqlDSN)
		if err != nil {
			t.Fatal("isolated MySQL unavailable")
		}
		defer fixture.Close()
		schema := "auth_chain_" + fmt.Sprint(time.Now().UnixNano())
		if _, err = fixture.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
			t.Fatal(err)
		}
		defer fixture.ExecContext(context.Background(), "DROP DATABASE `"+schema+"`")
		if _, err = fixture.ExecContext(ctx, "CREATE TABLE `"+schema+"`.authorization(id bigint PRIMARY KEY,appId varchar(32),appSecret varchar(128),accessOrganization varchar(128),status int,expired_at bigint)"); err != nil {
			t.Fatal(err)
		}
		if _, err = fixture.ExecContext(ctx, "INSERT INTO `"+schema+"`.authorization VALUES(8,'chain-app','chain-secret','chain',0,0)"); err != nil {
			t.Fatal(err)
		}
		cfg.Host, cfg.Port, cfg.Database, cfg.Username, cfg.Password = "127.0.0.1", 23306, schema, parsed.User, parsed.Passwd
		raw, _ = json.Marshal(cfg)
		if w = call(http.MethodPut, string(raw)); w.Code != 200 {
			t.Fatal("chain configuration save failed")
		}
		if w = call(http.MethodPost, ""); w.Code != 200 || strings.Contains(w.Body.String(), "chain-secret") {
			t.Fatal("read-only authorization check failed or leaked")
		}
		// The public endpoint persists a task; the recovered worker returns the
		// normal read-only database result without exposing either credential.
		s.tasks = &taskRuntime{dir: filepath.Join(t.TempDir(), "inputs"), wake: make(chan struct{}, 2)}
		s.tasks.once.Do(func() {})
		actor := Session{User: User{ID: "authorization-task-" + id}, Role: "admin", Permissions: rolePermissions("admin")}
		defer db.ExecContext(context.Background(), `DELETE FROM control_plane_tasks WHERE created_by=$1`, actor.User.ID)
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req = req.WithContext(context.WithValue(req.Context(), sessionContextKey{}, actor))
		accepted := httptest.NewRecorder()
		s.dispatchAPI(accepted, req, strings.TrimPrefix(path, "/api/v1"))
		if accepted.Code != 202 {
			t.Fatalf("authorization task submit: %d", accepted.Code)
		}
		var task operationTask
		if err = json.Unmarshal(accepted.Body.Bytes(), &task); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE control_plane_tasks SET status='running',worker_id='dead',lease_until=now()-interval '1 minute',attempts=1 WHERE task_id=$1`, task.TaskID); err != nil {
			t.Fatal(err)
		}
		if !s.runNextOperationTask("authorization-recovery") {
			t.Fatal("authorization task not recovered")
		}
		completed, err := s.readOperationTask(ctx, task.TaskID, actor)
		if err != nil || completed.Status != "completed" || completed.ResponseStatus != 200 || !strings.Contains(string(completed.Result), "chain-app") || strings.Contains(string(completed.Result), "chain-secret") {
			t.Fatal("authorization task business result invalid")
		}
		expectedSecret := "chain-secret"
		requests := 0
		nativeServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			r.ParseForm()
			if r.URL.Path == "/api/v2/auth/get-access-token" {
				if r.Form.Get("appId") != "chain-app" || r.Form.Get("appSecret") != expectedSecret {
					t.Error("database credentials not used by native client")
				}
				w.Write([]byte(`{"code":0,"data":{"access_token":"token","lifetime":60}}`))
			} else if r.URL.Path == "/api/v2/base/get-online-total" {
				w.Write([]byte(`{"code":0,"data":{"online_total":1}}`))
			} else {
				t.Error("unexpected mutation request")
			}
		}))
		defer nativeServer.Close()
		// Saved management configuration supports connectivity without any
		// authoritative inventory or private enforcement runtime.
		connector := ActionConnector{ConnectorID: id, ConnectorType: "srun4k", EndpointURL: nativeServer.URL, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nativeServer.Certificate().Raw}))}
		if _, err = s.probeManaged4K(ctx, connector, nil); err != nil {
			t.Fatal("managed connectivity failed", err)
		}
		if len(s.nativeActions) != 0 {
			t.Fatal("connectivity registered enforcement runtime")
		}
		client, err := srunapi.New(nativeServer.URL, "unused-static-app", "unused-static-secret", nativeServer.Client())
		if err != nil {
			t.Fatal(err)
		}
		s.nativeActions = map[string]NativeActionRuntime{id: {Client: client}}
		s.bind4KCredentialProviders()
		if _, err = s.nativeActions[id].Probe(ctx); err != nil {
			t.Fatal("database-to-native authentication chain failed")
		}
		expectedSecret = "rotated-chain-secret"
		if _, err = fixture.ExecContext(ctx, "UPDATE `"+schema+"`.authorization SET appSecret=? WHERE id=8", expectedSecret); err != nil {
			t.Fatal(err)
		}
		if _, err = s.nativeActions[id].Probe(ctx); err != nil {
			t.Fatal("credential rotation chain failed")
		}
		before := requests
		if _, err = fixture.ExecContext(ctx, "UPDATE `"+schema+"`.authorization SET status=1 WHERE id=8"); err != nil {
			t.Fatal(err)
		}
		if _, err = s.nativeActions[id].Probe(ctx); err == nil || requests != before {
			t.Fatal("disabled database authorization sent HTTP or fell back to static credentials")
		}
	}
	s.actionMasterKey = []byte("wrong-master-key")
	if _, _, err = s.load4KDatabase(ctx, id, true); err == nil {
		t.Fatal("incorrect master key accepted")
	}
}
