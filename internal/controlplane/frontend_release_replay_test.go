package controlplane

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrontendReleaseAssetReplay(t *testing.T) {
	root := t.TempDir()
	put := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	current := filepath.Join(root, "releases", "new")
	previous := filepath.Join(root, "releases", "old")
	for _, p := range []string{current, previous} {
		put(filepath.Join(p, "frontend/dist/index.html"), "<html>current shell</html>")
	}
	put(filepath.Join(current, "frontend/dist/assets/current.js"), "export const current=1;")
	put(filepath.Join(previous, "frontend/dist/assets/previous.js"), "export const previous=1;")
	put(filepath.Join(previous, "frontend/dist/assets/current.js"), "export const obsolete=1;")
	if err := os.Symlink(current, filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(previous, filepath.Join(root, "previous")); err != nil {
		t.Fatal(err)
	}
	s := &Server{frontendDir: filepath.Join(root, "current/frontend/dist")}
	check := func(t *testing.T, path string, status int, body string) {
		t.Helper()
		w := httptest.NewRecorder()
		s.serveFrontend(w, httptest.NewRequest("GET", path, nil))
		if w.Code != status || !strings.Contains(w.Body.String(), body) {
			t.Fatalf("%s: %d %q", path, w.Code, w.Body.String())
		}
		if status == http.StatusOK && strings.HasSuffix(path, ".js") && !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
			t.Fatalf("wrong asset type: %s", w.Header().Get("Content-Type"))
		}
	}
	t.Run("current wins", func(t *testing.T) { check(t, "/assets/current.js", 200, "current=1") })
	t.Run("open page retains previous chunk", func(t *testing.T) { check(t, "/assets/previous.js", 200, "previous=1") })
	t.Run("missing asset returns 404", func(t *testing.T) { check(t, "/assets/missing.js", 404, "404") })
	t.Run("SPA remains navigable", func(t *testing.T) { check(t, "/policies", 200, "current shell") })
	t.Run("outside previous rejected", func(t *testing.T) {
		outside := t.TempDir()
		put(filepath.Join(outside, "frontend/dist/assets/outside.js"), "outside secret")
		os.Remove(filepath.Join(root, "previous"))
		if err := os.Symlink(outside, filepath.Join(root, "previous")); err != nil {
			t.Fatal(err)
		}
		check(t, "/assets/outside.js", 404, "404")
	})
	t.Run("previous frontend escape rejected", func(t *testing.T) {
		os.Remove(filepath.Join(root, "previous"))
		if err := os.Symlink(previous, filepath.Join(root, "previous")); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		put(filepath.Join(outside, "assets/escape.js"), "private configuration")
		old := filepath.Join(previous, "frontend/dist")
		if err := os.Rename(old, old+".saved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, old); err != nil {
			t.Fatal(err)
		}
		check(t, "/assets/escape.js", 404, "404")
	})
	t.Run("traversal rejected", func(t *testing.T) {
		put(filepath.Join(root, "current/frontend/secret"), "private configuration")
		check(t, "/../secret", 404, "404")
	})
	t.Run("symlink asset rejected", func(t *testing.T) {
		secret := filepath.Join(root, "secret.js")
		put(secret, "private configuration")
		if err := os.Symlink(secret, filepath.Join(current, "frontend/dist/assets/link.js")); err != nil {
			t.Fatal(err)
		}
		check(t, "/assets/link.js", 404, "404")
	})
}

func TestFrontendRepeatedBackendUpgradeReplay(t *testing.T) {
	root := t.TempDir()
	for _, version := range []string{"ui-old", "backend-1", "backend-2"} {
		directory := filepath.Join(root, "releases", version, "frontend/dist/assets")
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(directory), "index.html"), []byte("<html>new graph</html>"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(root, "releases/ui-old/frontend/dist/assets/still-open.js")
	if err := os.WriteFile(old, []byte("export const oldPage=1;"), 0644); err != nil {
		t.Fatal(err)
	}
	for name, version := range map[string]string{"current": "backend-2", "previous": "backend-1", "frontend-previous": "ui-old"} {
		if err := os.Symlink(filepath.Join(root, "releases", version), filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{frontendDir: filepath.Join(root, "current/frontend/dist")}
	w := httptest.NewRecorder()
	s.serveFrontend(w, httptest.NewRequest("GET", "/assets/still-open.js", nil))
	if w.Code != 200 || w.Body.String() != "export const oldPage=1;" {
		t.Fatalf("open page lost across backend-only upgrades: %d %q", w.Code, w.Body.String())
	}
	os.Remove(filepath.Join(root, "frontend-previous"))
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(root, "frontend-previous"))
	w = httptest.NewRecorder()
	s.serveFrontend(w, httptest.NewRequest("GET", "/assets/still-open.js", nil))
	if w.Code != 404 {
		t.Fatalf("outside frontend pointer accepted: %d", w.Code)
	}
}
