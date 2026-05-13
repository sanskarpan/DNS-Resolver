package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed web/*
var embeddedWeb embed.FS

var (
	frontendFS        fs.FS
	frontendAvailable bool
)

func init() {
	sub, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		return
	}
	frontendFS = sub
	frontendAvailable = true
}

func (a *API) serveFrontend(w http.ResponseWriter, r *http.Request) bool {
	if !frontendAvailable || frontendFS == nil {
		return false
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if strings.HasPrefix(path, "api/") || strings.HasPrefix(path, "ws/") || strings.HasPrefix(path, "dns-query") || strings.HasPrefix(path, "debug/") || path == "metrics" {
		return false
	}
	if path == "" {
		path = "index.html"
	}
	if fi, err := fs.Stat(frontendFS, path); err == nil && !fi.IsDir() {
		http.FileServer(http.FS(frontendFS)).ServeHTTP(w, r)
		return true
	}
	if path != "" && strings.Contains(path, ".") {
		http.NotFound(w, r)
		return true
	}
	if index, err := fs.ReadFile(frontendFS, "index.html"); err == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(index)
		return true
	}
	return false
}
