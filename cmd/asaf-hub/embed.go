//go:build embed_ui

// Package main — Stargate UI embed declaration.
//
// This file is compiled ONLY when the `embed_ui` build tag is set,
// which happens automatically in the `build-hub` Makefile target after
// `npm run build` has populated the dist/ directory.
//
// Without the tag (dev builds via `go run ./cmd/asaf-hub`), the `dist/`
// directory is served directly from the filesystem, enabling hot-reload
// during development of both the Go backend and the Next.js frontend.
//
// Build pipeline:
//   1. cd Adinkhepra-ASAF && npm ci && npm run build
//   2. cp -r Adinkhepra-ASAF/out PQC-Khepra-MCP/cmd/asaf-hub/dist
//   3. cd PQC-Khepra-MCP && go build -tags embed_ui -o bin/asaf-hub.exe ./cmd/asaf-hub
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed dist
var stargateFS embed.FS

// stargateSubFS strips the "dist/" prefix so the embedded file system
// serves at "/" instead of "/dist/".
var stargateSubFS, _ = fs.Sub(stargateFS, "dist")

// setupEmbeddedUI mounts the embedded Next.js static export onto mux.
// This function replaces the filesystem-based setupStargateUI when
// compiled with the embed_ui build tag.
//
// The SPA routing pattern is:
//   - /asaf-config.js   → injected config (always dynamic, not embedded)
//   - /                 → dist/index.html
//   - /_next/*          → static assets
//   - /[unknown]        → dist/index.html (Next.js static export SPA fallback)
func setupEmbeddedUI(mux *http.ServeMux) {
	fileServer := http.FileServer(http.FS(stargateSubFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if isBackendRoute(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		// Try to serve the file directly
		if _, err := fs.Stat(stargateSubFS, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
			// Not found → SPA fallback to index.html
			indexHTML, _ := fs.ReadFile(stargateSubFS, "index.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write(indexHTML)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
