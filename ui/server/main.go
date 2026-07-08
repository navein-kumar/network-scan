package main

import (
	"crypto/subtle"
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed static
var staticFS embed.FS

// Server wires the store and HTTP routing.
const uiVersion = "1.1.1"

type Server struct {
	store    *Store
	folders  *FolderStore
	settings *SettingsStore
	spa      fs.FS
	spaIndex []byte
	authUser string
}

func main() {
	addr := flag.String("addr", ":8888", "listen address")
	_ = flag.String("token", "", "auth token (reserved, unused in v1)")
	authCreds := flag.String("auth", "", "HTTP basic auth user:pass (empty = no auth)")
	dataDir := flag.String("data", "data", "scan data directory")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("cannot create data dir: %v", err)
	}

	store := NewStore(*dataDir)
	store.loadFromDisk()

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}
	index, _ := fs.ReadFile(sub, "index.html")

	authUser := ""
	if *authCreds != "" {
		authUser, _, _ = strings.Cut(*authCreds, ":")
	}

	srv := &Server{
		store:    store,
		folders:  NewFolderStore(*dataDir),
		settings: NewSettingsStore(*dataDir),
		spa:      sub,
		spaIndex: index,
		authUser: authUser,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/", srv.routeAPI)
	mux.HandleFunc("/", srv.serveSPA)

	var handler http.Handler = mux
	if *authCreds != "" {
		handler = basicAuth(mux, *authCreds)
		log.Printf("basic auth ENABLED")
	}
	log.Printf("fastscan-ui listening on %s (data=%s)", *addr, *dataDir)
	log.Fatal(http.ListenAndServe(*addr, handler))
}

// routeAPI dispatches all /api/* requests.
func (srv *Server) routeAPI(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/")

	switch {
	case p == "meta" && r.Method == http.MethodGet:
		srv.handleMeta(w, r)
		return
	case p == "deps" && r.Method == http.MethodGet:
		srv.handleDeps(w, r)
		return
	case p == "settings" && r.Method == http.MethodGet:
		srv.handleGetSettings(w, r)
		return
	case p == "settings" && r.Method == http.MethodPut:
		srv.handlePutSettings(w, r)
		return
	case p == "scans/import" && r.Method == http.MethodPost:
		srv.handleImportScan(w, r)
		return
	case p == "scans/bulk-delete" && r.Method == http.MethodPost:
		srv.handleBulkDelete(w, r)
		return
	case p == "folders" && r.Method == http.MethodGet:
		srv.handleListFolders(w, r)
		return
	case p == "folders" && r.Method == http.MethodPost:
		srv.handleCreateFolder(w, r)
		return
	case p == "scans" && r.Method == http.MethodPost:
		srv.handleCreateScan(w, r)
		return
	case p == "scans" && r.Method == http.MethodGet:
		srv.handleListScans(w, r)
		return
	}

	// /api/scans/{id}[/sub]
	if rest, ok := strings.CutPrefix(p, "scans/"); ok {
		id, sub, _ := strings.Cut(rest, "/")
		if id == "" {
			writeErr(w, http.StatusNotFound, "scan id required")
			return
		}
		s, found := srv.store.get(id)
		if !found {
			writeErr(w, http.StatusNotFound, "scan not found")
			return
		}
		switch {
		case sub == "" && r.Method == http.MethodGet:
			srv.handleGetScan(w, s)
		case sub == "" && r.Method == http.MethodDelete:
			srv.handleDeleteScan(w, s)
		case sub == "findings" && r.Method == http.MethodGet:
			srv.handleFindings(w, s)
		case sub == "hosts" && r.Method == http.MethodGet:
			srv.handleHosts(w, s)
		case sub == "diff" && r.Method == http.MethodGet:
			srv.handleDiff(w, r, s)
		case sub == "stop" && r.Method == http.MethodPost:
			srv.handleStopScan(w, s)
		case sub == "pause" && r.Method == http.MethodPost:
			srv.handlePauseScan(w, s)
		case sub == "resume" && r.Method == http.MethodPost:
			srv.handleResumeScan(w, s)
		case sub == "rescan" && r.Method == http.MethodPost:
			srv.handleRescan(w, s)
		case sub == "stream" && r.Method == http.MethodGet:
			srv.handleStream(w, r, s)
		case sub == "export" && r.Method == http.MethodGet:
			srv.handleExport(w, r, s)
		case strings.HasPrefix(sub, "evidence/") && r.Method == http.MethodGet:
			evidenceForRule(w, s, strings.TrimPrefix(sub, "evidence/"))
		case sub == "move" && r.Method == http.MethodPost:
			srv.handleMoveScan(w, r, s)
		default:
			writeErr(w, http.StatusNotFound, "unknown scan route")
		}
		return
	}

	// /api/folders/{id}
	if rest, ok := strings.CutPrefix(p, "folders/"); ok {
		folderID, sub2, _ := strings.Cut(rest, "/")
		if folderID == "" {
			writeErr(w, http.StatusNotFound, "folder id required")
			return
		}
		_ = sub2
		switch {
		case r.Method == http.MethodDelete:
			srv.handleDeleteFolder(w, r, folderID)
		case r.Method == http.MethodPatch:
			srv.handleRenameFolder(w, r, folderID)
		default:
			writeErr(w, http.StatusNotFound, "unknown folder route")
		}
		return
	}

	writeErr(w, http.StatusNotFound, "unknown endpoint")
}

// serveSPA serves embedded static assets, falling back to index.html.
func (srv *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean("/"+r.URL.Path)), "/")
	if clean == "" {
		srv.writeIndex(w)
		return
	}
	if b, err := fs.ReadFile(srv.spa, clean); err == nil {
		w.Header().Set("Content-Type", contentType(clean))
		_, _ = w.Write(b)
		return
	}
	// SPA routing: any non-asset, non-/api path serves index.html.
	srv.writeIndex(w)
}

func (srv *Server) writeIndex(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(srv.spaIndex)
}

// contentType returns a MIME type from the file extension for SPA assets.
func contentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".ico":
		return "image/x-icon"
	case ".woff2":
		return "font/woff2"
	case ".woff":
		return "font/woff"
	case ".map":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

// basicAuth wraps a handler requiring HTTP Basic Auth matching creds "user:pass".
// Works with EventSource since browsers cache and resend basic-auth credentials
// for same-origin requests.
func basicAuth(next http.Handler, creds string) http.Handler {
	user, pass, _ := strings.Cut(creds, ":")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="fastscan-ui"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
