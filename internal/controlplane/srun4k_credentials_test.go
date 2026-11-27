package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSRun4KCredentialTransport(t *testing.T) {
	for _, tc := range []struct {
		name, host, peer string
		tls, allowed     bool
	}{
		{"public_http", "example.test", "192.0.2.4:12000", false, false},
		{"forwarded_header", "example.test", "127.0.0.1:12000", false, false},
		{"forged_host", "localhost", "192.0.2.4:12000", false, false},
		{"ssh_v4", "127.0.0.1:18090", "127.0.0.1:12000", false, true},
		{"ssh_v6", "[::1]:18090", "[::1]:12000", false, true},
		{"tls", "example.test", "192.0.2.4:12000", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/v1/integrations/srun4k/one", nil)
			req.Host, req.RemoteAddr = tc.host, tc.peer
			req.Header.Set("X-Forwarded-Proto", "https")
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if got := srun4KCredentialTransport(req); got != tc.allowed {
				t.Fatalf("allowed=%v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestSRun4KCredentialsPersistAndResolve(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO control_plane_settings`).WithArgs(srun4KCredentialsPrefix+"one", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO control_plane_settings`).WithArgs(srun4KCredentialsPrefix+"one", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := &Server{actionMasterKey: []byte("isolated-test-encryption-key"), srun4KDefaults: SRun4KDefaults{RedisPassword: "deployment-fallback"}}
	input := srun4KCredentialsInput{
		DatabaseUsername: "readonly-user", DatabasePassword: "database-test-secret",
		RedisPassword: "redis-test-secret",
	}
	saved, err := s.saveSRun4KCredentials(ctx, tx, "one", input, srun4KStoredCredentials{}, false, false, false)
	if err != nil || saved.EncryptedDatabase == input.DatabasePassword || saved.EncryptedRedis == input.RedisPassword || saved.Revision == "" {
		t.Fatalf("encrypted save failed: %v", err)
	}
	kept, err := s.saveSRun4KCredentials(ctx, tx, "one", srun4KCredentialsInput{}, saved, false, false, false)
	if err != nil || kept != saved {
		t.Fatal("blank edit must retain existing fields")
	}
	item := srun4KIntegration{ConnectorID: "one", AuthorizationDatabaseHost: "192.0.2.1", storedCredentials: saved}
	cfg, err := s.srunDatabase(ctx, item)
	if err != nil || cfg.Username != input.DatabaseUsername || cfg.Password != input.DatabasePassword {
		t.Fatal("configured database credentials were not used")
	}
	opt := s.srunRedisOptions(item, "192.0.2.2", 16380)
	_, password, err := opt.CredentialsProviderContext(ctx)
	if err != nil || password != input.RedisPassword {
		t.Fatal("configured Redis credentials were not used")
	}
	public, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{input.DatabaseUsername, input.DatabasePassword, input.RedisPassword, saved.EncryptedDatabase, saved.EncryptedRedis, saved.Revision} {
		if strings.Contains(string(public), secret) {
			t.Fatal("private configuration leaked into API response")
		}
	}
	changed, err := s.saveSRun4KCredentials(ctx, tx, "one", srun4KCredentialsInput{}, saved, true, true, false)
	if err != nil || changed.EncryptedDatabase != "" || changed.EncryptedRedis != "" || changed.Revision == saved.Revision {
		t.Fatal("host edit must invalidate affected credentials")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSRun4KCredentialInputValidation(t *testing.T) {
	for _, input := range []srun4KCredentialsInput{
		{DatabaseUsername: "only-user"},
		{DatabasePassword: "only-password"},
		{NorthboundCertificate: "not a certificate"},
	} {
		if input.validate() == nil {
			t.Fatal("invalid credential input accepted")
		}
	}
}
