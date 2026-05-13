package api

import (
	"net/http"
)

func (a *API) live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "alive"})
}

func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	if a.deps.ReadyCheck() {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready"})
}
