package controlplane

import (
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var hashedFrontendAsset = regexp.MustCompile(`-[A-Za-z0-9_-]{8,}\.(js|css)$`)

func acceptsFrontendGzip(value string) bool {
	for _, encoding := range strings.Split(value, ",") {
		parts := strings.Split(encoding, ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "gzip") {
			continue
		}
		quality := 1.0
		for _, parameter := range parts[1:] {
			key, raw, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if found && strings.EqualFold(key, "q") {
				q, err := strconv.ParseFloat(raw, 64)
				if err != nil || q < 0 || q > 1 {
					return false
				}
				quality = q
			}
		}
		return quality > 0
	}
	return false
}

// Compression happens when building the release, never in request workers.
// Both original and compressed files pass the same containment checks.
func serveFrontendFile(w http.ResponseWriter, r *http.Request, directory, name, target string) {
	ext := filepath.Ext(name)
	if strings.HasPrefix(name, "assets/") && (ext == ".js" || ext == ".css") {
		addVary(w.Header(), "Accept-Encoding")
		if hashedFrontendAsset.MatchString(filepath.Base(name)) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		if r.Header.Get("Range") == "" && acceptsFrontendGzip(r.Header.Get("Accept-Encoding")) {
			if compressed, ok := frontendRegularFile(directory, name+".gz"); ok {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", mime.TypeByExtension(ext))
				target = compressed
			}
		}
	} else if ext == ".html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeFile(w, r, target)
}

// Only public regular files inside the selected frontend directory are served.
func frontendRegularFile(directory, name string) (string, bool) {
	base, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", false
	}
	target := filepath.Join(directory, name)
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", false
	}
	relative, err := filepath.Rel(base, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return resolved, true
}

// The previous pointer is the upgrade tool's retained rollback release. A page
// opened before an upgrade may still request its immutable, hashed chunks.
func previousReleaseFrontend(directory string) (string, bool) {
	directory = filepath.Clean(directory)
	current := filepath.Dir(filepath.Dir(directory))
	root := filepath.Dir(current)
	if directory != filepath.Join(root, "current", "frontend", "dist") {
		return "", false
	}
	var err error
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	previousFrontend := ""
	names := []string{"current", "previous"}
	compat := filepath.Join(root, "frontend-previous")
	if _, err := os.Lstat(compat); err == nil {
		names = append(names, "frontend-previous")
	} else if !os.IsNotExist(err) {
		return "", false
	}
	for _, name := range names {
		pointer := filepath.Join(root, name)
		info, err := os.Lstat(pointer)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return "", false
		}
		release, err := filepath.EvalSymlinks(pointer)
		if err != nil || filepath.Dir(release) != filepath.Join(root, "releases") {
			return "", false
		}
		frontend := filepath.Join(pointer, "frontend", "dist")
		resolved, err := filepath.EvalSymlinks(frontend)
		if err != nil || resolved != filepath.Join(release, "frontend", "dist") {
			return "", false
		}
		if name == "previous" || name == "frontend-previous" {
			previousFrontend = resolved
		}
	}
	return previousFrontend, true
}
