package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Folder struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

type FolderStore struct {
	mu      sync.RWMutex
	path    string
	folders []Folder
}

func NewFolderStore(dataDir string) *FolderStore {
	fs := &FolderStore{path: filepath.Join(dataDir, "folders.json")}
	fs.load()
	if len(fs.folders) == 0 {
		fs.folders = []Folder{{
			ID:      "default",
			Name:    "Default",
			Created: time.Now().UTC().Format(time.RFC3339),
		}}
		fs.save()
	}
	return fs
}

func (fs *FolderStore) load() {
	b, err := os.ReadFile(fs.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &fs.folders)
}

func (fs *FolderStore) save() {
	b, _ := json.MarshalIndent(fs.folders, "", "  ")
	_ = os.WriteFile(fs.path, b, 0o644)
}

func newFolderID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("folder_%x", b)
}

func (fs *FolderStore) list() []Folder {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	out := make([]Folder, len(fs.folders))
	copy(out, fs.folders)
	return out
}

func (fs *FolderStore) create(name string) Folder {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f := Folder{ID: newFolderID(), Name: name, Created: time.Now().UTC().Format(time.RFC3339)}
	fs.folders = append(fs.folders, f)
	fs.save()
	return f
}

func (fs *FolderStore) deleteFolder(id string) bool {
	if id == "default" {
		return false
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for i, f := range fs.folders {
		if f.ID == id {
			fs.folders = append(fs.folders[:i], fs.folders[i+1:]...)
			fs.save()
			return true
		}
	}
	return false
}

func (fs *FolderStore) rename(id, name string) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for i, f := range fs.folders {
		if f.ID == id {
			fs.folders[i].Name = name
			fs.save()
			return true
		}
	}
	return false
}

// HTTP handlers

func (srv *Server) handleListFolders(w http.ResponseWriter, r *http.Request) {
	writeJSONResp(w, http.StatusOK, srv.folders.list())
}

func (srv *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	f := srv.folders.create(body.Name)
	writeJSONResp(w, http.StatusOK, f)
}

func (srv *Server) handleDeleteFolder(w http.ResponseWriter, r *http.Request, id string) {
	if !srv.folders.deleteFolder(id) {
		writeErr(w, http.StatusBadRequest, "folder not found or cannot be deleted")
		return
	}
	for _, sc := range srv.store.list() {
		sc.mu.Lock()
		if sc.Status.Config.FolderID == id {
			sc.Status.Config.FolderID = "default"
		}
		sc.mu.Unlock()
		sc.save()
	}
	writeJSONResp(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (srv *Server) handleRenameFolder(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if !srv.folders.rename(id, body.Name) {
		writeErr(w, http.StatusNotFound, "folder not found")
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]string{"status": "renamed"})
}

func (srv *Server) handleMoveScan(w http.ResponseWriter, r *http.Request, sc *Scan) {
	var body struct {
		FolderID string `json:"folder_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	sc.mu.Lock()
	sc.Status.Config.FolderID = body.FolderID
	sc.mu.Unlock()
	sc.save()
	writeJSONResp(w, http.StatusOK, map[string]string{"status": "moved"})
}

func (srv *Server) handleBulkDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	deleted := 0
	for _, id := range body.IDs {
		if sc, ok := srv.store.get(id); ok {
			sc.mu.Lock()
			running := sc.Status.State == "running"
			sc.mu.Unlock()
			if !running {
				srv.store.remove(id)
				deleted++
			}
		}
	}
	writeJSONResp(w, http.StatusOK, map[string]int{"deleted": deleted})
}
