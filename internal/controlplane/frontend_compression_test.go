package controlplane

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrontendPrecompressedReplay(t *testing.T) {
	dir := t.TempDir()
	name := "assets/queries-abcdefgh.js"
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("export const replay = 1;\n", 100)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write([]byte(body))
	gz.Close()
	if err := os.WriteFile(filepath.Join(dir, name+".gz"), compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{frontendDir: dir}
	for _, tc := range []struct {
		accept, rangeHeader string
		gzip                bool
	}{
		{"gzip", "", true}, {"br, gzip;q=0.5", "", true}, {"gzip;q=0", "", false}, {"gzip;q=invalid", "", false}, {"", "", false}, {"gzip", "bytes=0-9", false},
	} {
		r := httptest.NewRequest("GET", "/"+name, nil)
		r.Header.Set("Accept-Encoding", tc.accept)
		r.Header.Set("Range", tc.rangeHeader)
		w := httptest.NewRecorder()
		s.serveFrontend(w, r)
		if (w.Header().Get("Content-Encoding") == "gzip") != tc.gzip {
			t.Fatal("negotiation failed", tc, w.Header())
		}
		if !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
			t.Fatal("asset headers", w.Header())
		}
		if tc.gzip {
			reader, err := gzip.NewReader(w.Body)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || string(raw) != body {
				t.Fatal("corrupt compressed asset", err)
			}
		}
	}
	// An untrusted compressed symlink cannot disclose a file outside the release.
	os.Remove(filepath.Join(dir, name+".gz"))
	private := filepath.Join(t.TempDir(), "private")
	os.WriteFile(private, []byte("secret"), 0600)
	if err := os.Symlink(private, filepath.Join(dir, name+".gz")); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/"+name, nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	s.serveFrontend(w, r)
	if w.Body.String() != body || w.Header().Get("Content-Encoding") != "" {
		t.Fatal("compressed containment failed")
	}
}
